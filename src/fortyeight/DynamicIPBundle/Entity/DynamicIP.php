<?php

namespace fortyeight\DynamicIPBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * DynamicIP
 *
 * @ORM\Table(name="fortyeight_dynamic_ip")
 * @ORM\Entity
 */
class DynamicIP
{
    /**
     * @var integer
     *
     * @ORM\Column(name="id", type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private $id;

    /**
     * @var \DateTime
     *
     * @ORM\Column(name="created_at", type="datetime")
     */
    private $createdAt;

    /**
     * @var \DateTime
     *
     * @ORM\Column(name="updated_at", type="datetime")
     */
    private $updatedAt;

    /**
    * @var \DateTime
    *
    * @ORM\Column(name="refreshed_at", type="datetime", nullable=true)
    */
    private $refreshedAt;

    /**
    * @var \DateTime
    *
    * @ORM\Column(name="ping_at", type="datetime", nullable=true)
    */
    private $pingAt;

    /**
     * @var string
     *
     * @ORM\Column(name="title", type="string", length=127, nullable=true)
     */
    private $title;

    /**
     * @var string
     *
     * @ORM\Column(name="hash", type="string", length=8, unique=true)
     */
    private $hash;

    /**
     * @var string
     *
     * @ORM\Column(name="ip", type="string", length=15, unique=true)
     */
    private $ip;

    /**
     * @var string
     *
     * @ORM\Column(name="token", type="string", length=32, unique=true)
     */
    private $token;

    /**
     * @ORM\ManyToOne(targetEntity="\VoIP\Company\StructureBundle\Entity\Company", inversedBy="dynIPs")
     * @ORM\JoinColumn(name="company_id", referencedColumnName="id", onDelete="CASCADE")
     */
    private $company;

    /**
     * @ORM\PrePersist
     */
    public function prePersist()
    {
        $this->setCreatedAt(new \DateTime());
        $this->setUpdatedAt(new \DateTime());
        $this->setHash(hash('crc32b', uniqid()));
        $this->setToken(hash('md5', uniqid()));
    }

    /**
     * @ORM\PreUpdate
     */
    public function preUpdate()
    {
        $this->setUpdatedAt(new \DateTime());
    }


    /**
     * Get id
     *
     * @return integer 
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Set createdAt
     *
     * @param \DateTime $createdAt
     * @return DynamicIP
     */
    public function setCreatedAt($createdAt)
    {
        $this->createdAt = $createdAt;

        return $this;
    }

    /**
     * Get createdAt
     *
     * @return \DateTime 
     */
    public function getCreatedAt()
    {
        return $this->createdAt;
    }

    /**
     * Set updatedAt
     *
     * @param \DateTime $updatedAt
     * @return DynamicIP
     */
    public function setUpdatedAt($updatedAt)
    {
        $this->updatedAt = $updatedAt;

        return $this;
    }

    /**
     * Get updatedAt
     *
     * @return \DateTime 
     */
    public function getUpdatedAt()
    {
        return $this->updatedAt;
    }

    /**
     * Set refreshedAt
     *
     * @param \DateTime $refreshedAt
     * @return DynamicIP
     */
    public function setRefreshedAt($refreshedAt)
    {
        $this->refreshedAt = $refreshedAt;

        return $this;
    }

    /**
     * Get refreshedAt
     *
     * @return \DateTime 
     */
    public function getRefreshedAt()
    {
        return $this->refreshedAt;
    }

    /**
     * Set pingAt
     *
     * @param \DateTime $pingAt
     * @return DynamicIP
     */
    public function setPingAt($pingAt)
    {
        $this->pingAt = $pingAt;

        return $this;
    }

    /**
     * Get pingAt
     *
     * @return \DateTime 
     */
    public function getPingAt()
    {
        return $this->pingAt;
    }

    /**
     * Set title
     *
     * @param string $title
     * @return DynamicIP
     */
    public function setTitle($title)
    {
        $this->title = $title;

        return $this;
    }

    /**
     * Get title
     *
     * @return string 
     */
    public function getTitle()
    {
        return $this->title;
    }

    /**
     * Set hash
     *
     * @param string $hash
     * @return DynamicIP
     */
    public function setHash($hash)
    {
        $this->hash = $hash;

        return $this;
    }

    /**
     * Get hash
     *
     * @return string 
     */
    public function getHash()
    {
        return $this->hash;
    }

    /**
     * Set ip
     *
     * @param string $ip
     * @return DynamicIP
     */
    public function setIp($ip)
    {
        $this->ip = $ip;

        return $this;
    }

    /**
     * Get ip
     *
     * @return string 
     */
    public function getIp()
    {
        return $this->ip;
    }

    /**
     * Set token
     *
     * @param string $token
     * @return DynamicIP
     */
    public function setToken($token)
    {
        $this->token = $token;

        return $this;
    }

    /**
     * Get token
     *
     * @return string 
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * Set company
     *
     * @param \VoIP\Company\StructureBundle\Entity\Company $company
     * @return DynamicIP
     */
    public function setCompany(\VoIP\Company\StructureBundle\Entity\Company $company = null)
    {
        $this->company = $company;

        return $this;
    }

    /**
     * Get company
     *
     * @return \VoIP\Company\StructureBundle\Entity\Company 
     */
    public function getCompany()
    {
        return $this->company;
    }
}
