# Ultimo ACL MVC
Access control list for Ultimo MVC

## Requirements

* PHP 5.3
* Ultimo ACL
* Ultimo Phptpl MVC
* Ultimo MVC
* Ultimo Session

## Usage
### Register plugin
	// create application ACL (privileges are added in each module)
	$acl = new \ultimo\security\Acl();
	$acl->addRole('guest');
	$acl->addRole('moderator', array('guest'));
	$acl->addRole('webmaster', array('guest'));
	$acl->addRole('admin', array('moderator', 'webmaster'));
	
	// Create a default (guest) user
	$guestUser = new \some\User(); // The User class must implement \ultimo\security\mvc\User
	$guestUser->id = 0;
	$guestUser->role = 'guest';
	
	// Register plugin
	$application->addPlugin(new \ultimo\security\mvc\plugins\Authorizer($guestUser, $acl), 'authorizer');

### Add module roles and privileges in Module
	namespace modules\newsbulletin;
	
	class Module extends \ultimo\mvc\Module implements \ultimo\security\mvc\AuthorizedModule {
	  
	  public function getAcl() {
	    $acl = new \ultimo\security\Acl();
	    // add module roles (if the module has a parent, module roles should be defined there)
	    $acl->addRole('newsbulletin.guest');
	    $acl->addRole('newsbulletin.admin');
	    
	    // link application roles to module roles
	    $acl->addRole('guest', array('newsbulletin.guest'));
	    $acl->addRole('webmaster', array('newsbulletin.admin'));
	    
	    // add privileges (if the module has a parent, privileges should be defined there)
	    $acl->allow('newsbulletin.guest', array('message.read'));
	    $acl->allow('newsbulletin.webmaster');
	    
	    return $acl;
	  }
	}

### Check priviliges in View
	<?php if ($this->authorizer()->isAllowed('message.read')): ?>
		<a href="link-to-message>Message</a>
	<?php endif ?>