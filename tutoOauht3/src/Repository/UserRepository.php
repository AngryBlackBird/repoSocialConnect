<?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\PasswordUpgraderInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * @method User|null find($id, $lockMode = null, $lockVersion = null)
 * @method User|null findOneBy(array $criteria, array $orderBy = null)
 * @method User[]    findAll()
 * @method User[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class UserRepository extends ServiceEntityRepository implements PasswordUpgraderInterface
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    /**
     * Used to upgrade (rehash) the user's password automatically over time.
     */
    public function upgradePassword(UserInterface $user, string $newEncodedPassword): void
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', \get_class($user)));
        }

        $user->setPassword($newEncodedPassword);
        $this->_em->persist($user);
        $this->_em->flush();
    }

    public function findOrCreateFromOauth(ResourceOwnerInterface $owner, string $service): User
    {
        $user = $this->createQueryBuilder('u')
            ->where('u.githubId = :githubId')
            ->orWhere('u.googleId = :googleId')
            ->orWhere('u.facebookId = :facebookId')
            ->setParameters(['githubId' => $owner->getId(), 'googleId' => $owner->getId(), 'facebookId' => $owner->getId()])
            ->getQuery()
            ->getOneOrNullResult();
        if ($user) {
            return $user;
        }

        $user = $this->createQueryBuilder('u')
            ->where('u.email = :email')
            ->setParameters(['email' => $owner->getEmail()])
            ->getQuery()
            ->getOneOrNullResult();
        if ($user) {
            if ($service == 'github') {
                $user->setGithubId($owner->getId());
            }
            if ($service == 'google') {
                $user->setGoogleId($owner->getId());
            }
            if ($service == 'facebook') {
                $user->setFacebookId($owner->getId());
            }
            $em = $this->getEntityManager();
            $em->persist($user);
            $em->flush();
            return $user;
        }

        if ($service == 'github') {
            $user = (new User())
                ->setRoles(['ROLE_USER'])
                ->setGithubId($owner->getId())
                ->setEmail($owner->getEmail());
        }
        if ($service == 'google') {
            $user = (new User())
                ->setRoles(['ROLE_USER'])
                ->setGoogleId($owner->getId())
                ->setEmail($owner->getEmail());
        }
        if ($service == 'facebook') {
            $user = (new User())
                ->setRoles(['ROLE_USER'])
                ->setFacebookId($owner->getId())
                ->setEmail($owner->getEmail());
        }
        $em = $this->getEntityManager();
        $em->persist($user);
        $em->flush();
        return $user;
    }
}
