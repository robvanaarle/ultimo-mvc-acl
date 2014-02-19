<?php

namespace ultimo\security\mvc\plugins\synology\ds;

class Authorizer implements \ultimo\mvc\plugins\ApplicationPlugin {
  
  protected $forcedUser = null;
  
  public function forceUser(User $user) {
    $this->forcedUser = $user;
  }
  
  /**
   * Called after the plugin is added to an application.
   * @param \ultimo\mvc\Application $application The application the plugin is
   * added to.
   */
  public function onPluginAdded(\ultimo\mvc\Application $application) {
    // create ACL
    $acl = new \ultimo\security\Acl();
    $acl->addRole('guest');
    $acl->addRole('user', array('guest'));
    $acl->addRole('administrator', array('user'));
    
    // create guest user
    $guestUser = new User();
    $guestUser->id = 0;
    $guestUser->role = 'guest';
    
    // create authorizer
    $authorizer = new \ultimo\security\mvc\plugins\Authorizer($guestUser, $acl);
    $application->addPlugin($authorizer, 'authorizer');
    
    if ($this->forcedUser !== null) {
      $authorizer->setUser($this->forcedUser);
      return;
    }
    
    // get current user using the sdk
    // Caching the sdk user using the synology cookie 'id' does not work, as
    // this value does not change on logout (it does on login)
    $core = new \ultimo\sdk\synology\ds\Core();
    $user = new User();
    try {
      $user->username = $core->authenticate();
    } catch (\ultimo\sdk\synology\ds\Exception $e) {
      $user->username = null;
    }
    $user->role = 'guest';
    
    if ($user->username === null) {
      $user->id = 0;
    } else {
      $user->id = $core->getUserId($user->username);
      $groups = $core->getUserGroupIds($user->username);
      
      // find out if user is admin or user (or maybe guest)
      if (in_array(\ultimo\sdk\synology\ds\Core::GROUPID_ADMINISTRATORS, $groups)) {
        $user->role = 'administrator';
      } elseif (in_array(\ultimo\sdk\synology\ds\Core::GROUPID_USERS, $groups)) {
        $user->role = 'user';
      }
    }
    
    $authorizer->setUser($user);
  }
  
  public function onModuleCreated(\ultimo\mvc\Module $module) { }
  
  public function onRoute(\ultimo\mvc\Application $application, \ultimo\mvc\Request $request) { }
  
  public function onRouted(\ultimo\mvc\Application $application, \ultimo\mvc\Request $request=null) { }

  public function onDispatch(\ultimo\mvc\Application $application) { }
  
  public function onDispatched(\ultimo\mvc\Application $application) { }
}