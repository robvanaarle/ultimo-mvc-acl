<?php

namespace ultimo\security\mvc\plugins;

class ModuleAuthorizer implements \ultimo\mvc\plugins\ModulePlugin {
  
  /**
   * The creator of the plugin.
   * @var Authorizer
   */
  protected $authorizer;
  
  /**
   * The module the plugin is for.
   * @var \ultimo\mvc\Module
   */
  protected $module;
  
  /**
   * The cached module accesslist.
   * @var 
   */
  protected $acl = false;
  
  /**
   * Constructor.
   * @param Authorizer $authorizer The creator of the plugin.
   * @param \ultimo\mvc\Module $module The module the plugin is for.
   */
  public function __construct(Authorizer $authorizer, \ultimo\mvc\Module $module) {
    $this->authorizer = $authorizer;
    $this->module = $module;
  }
  
  /**
   * Returns the accesslist of the module.
   * @return \ultimo\security\Acl The accesslist of the module.
   */
  public function getAcl() {
    if ($this->acl === false) {
      $this->acl = $this->authorizer->getAcl($this->module->getNamespace());
    }
    return $this->acl;
  }
  
  /**
   * Returns the user using the application.
   * @return \ultimo\security\mvc\User The user using the application.
   */
  public function getUser() {
    return $this->authorizer->getUser();
  }
  
  /**
   * Returns whether the user using the application belongs to the specified
   * role.
   * @param string $role The name of the role.
   * @return boolean Whether the user using the application belongs to the
   * specified role.
   */
  public function isRole($role) {
    $acl = $this->getAcl();
    if ($acl === null) {
      return true;
    }
    
    $user = $this->getUser();
    if ($user === null) {
      return false;
    }
    
    return $acl->belongsTo($user->getRole(), $role);
  }
  
  /**
   * Returns whether the user using the application has permission to the
   * specified privilege.
   * @param string $privilege The name of the privilege.
   * @param mixed $callbackParam The custom parameter for the callback function
   * of the privilege.
   * @return boolean Whether the user using the application has permission to
   * the specified privilege.
   */
  public function isAllowed($privilege, $callbackParam = null) {
    return $this->getAcl()->isAllowed($this->getUser()->getRole(), $privilege, $callbackParam);
  }
  
  /**
   * Returns whether the user using the application has permission to the
   * specified privilege. If not, the request is forwarded to the
   * 'accessDenied' action.
   * @param string $privilege The name of the privilege.
   * @param mixed $callbackParam The custom parameter for the callback function
   * of the privilege.
   * @return boolean Whether the user using the application has permission to
   * the specified privilege.
   */
  public function checkAllowed($privilege, $callbackParam = null) {
    if (!$this->isAllowed($privilege, $callbackParam)) {
      $this->handleAccessDenied();
      return false;
    }
    return true;
  }
  
  /**
   * Forwards the current request to an 'accessDenied' action.
   */
  public function handleAccessDenied() {
    $this->authorizer->handleAccessDenied();
  }
  
  /**
   * Adds the creator of the plugin as controller plugin to the created
   * controller.
   */
  public function onControllerCreated(\ultimo\mvc\Controller $controller) {
    $controller->addPlugin($this->authorizer);
  }
}