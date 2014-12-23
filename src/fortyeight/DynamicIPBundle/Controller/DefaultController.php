<?php

namespace fortyeight\DynamicIPBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Security;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Method;
use fortyeight\DynamicIPBundle\Entity\DynamicIP as DynIP;
use Aws\Common\Aws;
use Aws\S3\Exception\S3Exception;
use Symfony\Component\HttpFoundation\JsonResponse;

class DefaultController extends Controller
{
    /**
     * @Route("/", name="homepage")
	 * @Security("has_role('ROLE_USER')")
     * @Template()
     */
    public function indexAction()
    {
    	$user = $this->getUser();
    	$em = $this->getDoctrine()->getManager();
    	$ip = $this->container->get('request')->getClientIp();

    	if (preg_match('/\d{1,3}(\.\d{1,3}){3}/', $ip) == 1) {
    		$dynIP = $em->getRepository('fortyeightDynamicIPBundle:DynamicIP')->findOneBy(array(
    			'ip' => $ip
    		));
    	} else {
    		$dynIP = null;
    		$ip = null;
    	}

    	$dynIPs = $em->getRepository('fortyeightDynamicIPBundle:DynamicIP')->findBy(array(), array(
    		'title' => 'ASC'
    	));

    	return array(
    		'dynIPs' => $dynIPs,
    		'dynIP' => $dynIP,
    		'ip' => $ip
    	);
    }
    /**
	 * @Route("/add-ip", name="add_ip")
	 * @Template()
	 * @Method("GET")
	 * @Security("has_role('ROLE_USER')")
	 */
	public function dynamicAddIPAction()
	{

		$request = $this->getRequest();
		$query = $request->query;

		$ip = $query->get('ip');
		$title = $query->get('title');

		if (!$ip) $ip = $this->container->get('request')->getClientIp();

		if (preg_match('/\d{1,3}(\.\d{1,3}){3}/', $ip) == 1) {
			$em = $this->getDoctrine()->getManager();
			$dynIP = $em->getRepository('fortyeightDynamicIPBundle:DynamicIP')->findOneBy(array(
				'ip' => $ip
			));
			if (!$dynIP) {
				$dynIP = new DynIP();
				$dynIP->setIp($ip);
				$dynIP->setTitle($title);
				$em->persist($dynIP);
				$em->flush();

				$authorizeResp = $this->firewallAddIP($ip, $this->container->getParameter('aws_group_id'));
				//$authorizeResp = $this->firewallAddIP($ip, 'sg-2f4a8b7a');
			}
		}

		return $this->redirect($this->generateUrl('homepage'));
	}

	/**
	 * @Route("/dynamic-network/remove-ip/{hash}", name="remove_ip")
	 * @Template()
	 * @Method("GET")
	 * @Security("has_role('ROLE_USER')")
	 */
	public function dynamicRemoveIPAction($hash)
	{

		$em = $this->getDoctrine()->getManager();
		$dynIP = $em->getRepository('fortyeightDynamicIPBundle:DynamicIP')->findOneBy(array(
			'hash' => $hash
		));
		if ($dynIP) {
			$ip = $dynIP->getIp();

			$em->remove($dynIP);
			$em->flush();

			$revokeResp = $this->firewallRemoveIP($ip, $this->container->getParameter('aws_group_id'));
			//$revokeResp = $this->firewallRemoveIP($ip, 'sg-2f4a8b7a');

		}

		return $this->redirect($this->generateUrl('homepage'));
	}

	/**
	 * @Route("/dynamic-network/update-ip/{hash}", name="update_ip")
	 * @Template()
	 * @Method("GET")
	 * @Security("has_role('ROLE_USER')")
	 */
	public function dynamicUpdateIPAction($hash)
	{
		$request = $this->getRequest();
		$query = $request->query;

		$em = $this->getDoctrine()->getManager();
		$dynIP = $em->getRepository('fortyeightDynamicIPBundle:DynamicIP')->findOneBy(array(
			'hash' => $hash
		));

		$ip = $query->get('ip');
		if (!$ip) $ip = $this->container->get('request')->getClientIp();
		if (preg_match('/\d{1,3}(\.\d{1,3}){3}/', $ip) == 1) {
			$dynIP2 = $em->getRepository('fortyeightDynamicIPBundle:DynamicIP')->findOneBy(array(
				'ip' => $ip
			));
			if ($dynIP && !$dynIP2) {
				$revokeResp = $this->firewallRemoveIP($dynIP->getIp(), $this->container->getParameter('aws_group_id'));
				//$revokeResp = $this->firewallRemoveIP($dynIP->getIp(), 'sg-2f4a8b7a');

				$dynIP->setIp($ip);
				$em->flush();

				$authorizeResp = $this->firewallAddIP($ip, $this->container->getParameter('aws_group_id'));
				//$authorizeResp = $this->firewallAddIP($ip, 'sg-2f4a8b7a');

			}
		}
		return $this->redirect($this->generateUrl('homepage'));
	}

	/**
	 * @Route("/public/{token}", name="public")
	 * @Template()
	 * @Method("GET")
	 */
	public function publicAction($token)
	{
		$request = $this->getRequest();
		$query = $request->query;

		$em = $this->getDoctrine()->getManager();
		$dynIP = $em->getRepository('fortyeightDynamicIPBundle:DynamicIP')->findOneBy(array(
			'token' => $token
		));

		$ip = $this->container->get('request')->getClientIp();

		if (preg_match('/\d{1,3}(\.\d{1,3}){3}/', $ip) == 1) {
			$dynIP2 = $em->getRepository('fortyeightDynamicIPBundle:DynamicIP')->findOneBy(array(
				'ip' => $ip
			));
			$response = new JsonResponse();
			if ($dynIP && !$dynIP2) {

				if ($ip != $dynIP->getIp()) {
					$revokeResp = $this->firewallRemoveIP($dynIP->getIp(), $this->container->getParameter('aws_group_id'));
					//$revokeResp = $this->firewallRemoveIP($dynIP->getIp(), 'sg-2f4a8b7a');

					$dynIP->setIp($ip);
					$dynIP->setRefreshedAt(new \DateTime());
					$dynIP->setPingAt(new \DateTime());
					$em->flush();

					$authorizeResp = $this->firewallAddIP($ip, $this->container->getParameter('aws_group_id'));
					//$authorizeResp = $this->firewallAddIP($ip, 'sg-2f4a8b7a');

					$response->setData(array(
						'auth' => true,
						'rev' => true,
						'previp' => $ip,
						'newip' => $ip
					));
				} else {
					$dynIP->setPingAt(new \DateTime());
					$em->flush();
					$response->setData(array(
						'auth' => 'no change',
						'rev' => 'no change',
						'ip' => $ip
					));
				}


			} else {
				$dynIP->setPingAt(new \DateTime());
				$em->flush();
				$response->setData(array(
					'dyn-ip' => !$dynIP ? 'not found' : 'already in list'
				));
			}
			$dynIP->setPingAt(new \DateTime());
			$em->flush();
		}

		
		return $response;
	}

	public function firewallAddIP($ip, $groupId)
	{
		$aws = Aws::factory(array(
			'key'    => $this->container->getParameter('aws_key'),
			'secret' => $this->container->getParameter('aws_secret'),
			'region' => 'ap-southeast-1'
		));
		return $aws->get('ec2')->authorizeSecurityGroupIngress(array(
			'GroupId' => $groupId,
			'IpPermissions' => array(
				array(
					'IpProtocol' => 'udp',
					'FromPort' => '5060',
					'ToPort' => '5060',
					'IpRanges' => array(
						array('CidrIp' => $ip.'/32'),
					)
				),
				array(
					'IpProtocol' => 'udp',
					'FromPort' => '10000',
					'ToPort' => '30000',
					'IpRanges' => array(
						array('CidrIp' => $ip.'/32'),
					)
				)
			)
		));
	}
	public function firewallRemoveIP($ip, $groupId = 'sg-8d9c5de8')
	{
		$aws = Aws::factory(array(
			'key'    => $this->container->getParameter('aws_key'),
			'secret' => $this->container->getParameter('aws_secret'),
			'region' => 'ap-southeast-1'
		));
		$ec2 = $aws->get('ec2')->revokeSecurityGroupIngress(array(
			'GroupId' => $groupId,
			'IpPermissions' => array(
				array(
					'IpProtocol' => 'udp',
					'FromPort' => '5060',
					'ToPort' => '5060',
					'IpRanges' => array(
						array('CidrIp' => $ip.'/32'),
					)
				),
				array(
					'IpProtocol' => 'udp',
					'FromPort' => '10000',
					'ToPort' => '30000',
					'IpRanges' => array(
						array('CidrIp' => $ip.'/32'),
					)
				)
			)
		));
		return $ec2; 
	}
}
