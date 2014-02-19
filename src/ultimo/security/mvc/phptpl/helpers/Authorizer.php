<?php

namespace ultimo\security\mvc\phptpl\helpers;

class Authorizer extends \ultimo\phptpl\mvc\Helper {
  /**
   * Helper initial function.
   * @return Authorizer This instance.
   */
  public function __invoke() {
    return $this;
  }
  
  /**
   * Returns the user using the application.
   * @return \ultimo\security\mvc\User The user using the application.
   */
  public function getUser() {
    return $this->application->getPlugin('authorizer')->getUser();
  }
  
  /**
   * Returns the id of the user using the application.
   * @return mixed The id of the user using the application.
   */
  public function getUserId() {
    return $this->getUser()->getId();
  }
  
  /**
   * Returns whether the user using the application has permission to the
   * specified privilege.
   * @param string $privilege The name of the privilege.
   * @param mixed $callbackParam The custom parameter for the callback function
   * of the privilege.
   * @param $moduleNamespace The namespace of the module to check the privilege
   * for.
   * @return boolean Whether the user using the application has permission to
   * the specified privilege.
   */
  public function isAllowed($privilege, $callbackParam = null, $moduleNamespace=null) {
    if ($moduleNamespace === null) {
      $moduleNamespace = $this->module->getNamespace();
    }
    $acl = $this->application->getPlugin('authorizer')->getAcl($moduleNamespace);
    if ($acl === null) {
      return true;
    }
    
    $user = $this->getUser();
    if ($user === null) {
      return false;
    }
    
    return $acl->isAllowed($user->getRole(), $privilege, $callbackParam);
  }
  
  /**
   * Returns whether the user using the application belongs to the specified
   * role.
   * @param string $role The name of the role.
   * @param $moduleNamespace The namespace of the module to check the role for.
   * @return boolean Whether the user using the application belongs to the
   * specified role.
   */
  public function isRole($role, $moduleNamespace=null) {
    if ($moduleNamespace === null) {
      $moduleNamespace = $this->module->getNamespace();
    }
    $acl = $this->application->getPlugin('authorizer')->getAcl($moduleNamespace);
    if ($acl === null) {
      return true;
    }
    
    $user = $this->getUser();
    if ($user === null) {
      return false;
    }
    
    return $acl->belongsTo($user->getRole(), $role);
  }
  
}