<?php

namespace ultimo\security\mvc\plugins;

class Authorizer implements \ultimo\mvc\plugins\ApplicationPlugin, \ultimo\mvc\plugins\ControllerPlugin {
  
  /**
   * The accesslist of the application.
   * @var \ultimo\security\Acl
   */
  protected $acl;
  
  /**
   * The session to store data in.
   * @var \ultimo\util\net\Session
   */
  protected $session;
  
  /**
   * The default user object for unseen users to the application.
   * @var \ultimo\security\mvc\User
   */
  protected $guestUser;
  
  /**
   * The application the authorizer is for.
   * @var \ultimo\mvc\Application
   */
  protected $application;
  
  /**
   * The cached modules accesslists merged with the application accesslist, a
   * hashtable with modulenamespaces as key and their accesslist as value.
   * @var array
   */
  protected $moduleAcls = array();
  
  /**
   * Called after the plugin is added to an application.
   * @param \ultimo\mvc\Application $application The application the plugin is
   * added to.
   */
  public function onPluginAdded(\ultimo\mvc\Application $application) {
    $this->application = $application;
  }
  
  /**
   * Constructor.
   * @param \ultimo\mvc\Application $application The application the authorizer
   * is for.
   * @param \ultimo\security\mvc\User $guestUser The default user object for
   * unseen users to the application.
   * @param \ultimo\security\Acl $acl The accesslist of the application.
   */
  public function __construct(\ultimo\security\mvc\User $guestUser, \ultimo\security\Acl $acl = null) {
    $this->guestUser = $guestUser;
    $this->session = new \ultimo\util\net\Session('Authorizer');
    if ($this->getUser() === null) {
      $this->setUser(null);
    }
    $this->acl = $acl;
  }
  
  /**
   * Sets the user using the application. The is generally done after
   * authentication.
   * @param \ultimo\security\mvc\User $user The user using the application, ot
   * null to set the guest user.
   */
  public function setUser(\ultimo\security\mvc\User $user=null) {
    if ($user === null) {
      $user = $this->guestUser;
    }
    $this->session->user = $user;
  }
  
  /**
   * Returns the user using the application.
   * @return \ultimo\security\mvc\User The user using the application.
   */
  public function getUser() {
    return $this->session->user;
  }
  
  /**
   * Returns the accesslist for the specfied module merged with the application
   * accesslist.
   * @param string $moduleNamespace The namespace of the module to get
   * the accesslist for, or null to get the application acl.
   * @return \ultimo\security\Acl The accesslist of the module, or null if the
   * module with the specfied namespace does not exist or does not have an
   * accesslist specified.
   */
  public function getAcl($moduleNamespace=null) {
    if ($moduleNamespace === null) {
      return $this->acl;
    }
    
    if (!array_key_exists($moduleNamespace, $this->moduleAcls)) {
      $module = $this->application->getModule($moduleNamespace);

      if ($module === null || !$module instanceof \ultimo\security\mvc\AuthorizedModule) {
        return null;
      }
      
      $moduleAcl = $module->getAcl();
      
      if ($moduleAcl === null) {
        return null;
      }
      
      $applicationAcl = $this->acl;
      if ($applicationAcl === null) {
        return null;
      }
        
      $totalAcl = clone $moduleAcl;
      $totalAcl->merge($applicationAcl);
      $this->moduleAcls[$moduleNamespace] = $totalAcl;
    }
    
    return $this->moduleAcls[$moduleNamespace];
  }
  
  /**
   * Appends the ModuleAuthorizer to the constructed module, and the Authorizer
   * view helper to the view.
   */
  public function onModuleCreated(\ultimo\mvc\Module $module) {
    $module->addPlugin(new ModuleAuthorizer($this, $module), 'authorizer');
    
    // add the view helpers directory, if the view is phptpl
    $view = $module->getView();
    if ($view instanceof \ultimo\phptpl\Engine) {
      $helperPath = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'phptpl' . DIRECTORY_SEPARATOR . 'helpers';
      
      $nsElems = explode('\\', __NAMESPACE__);
      array_pop($nsElems);
      array_push($nsElems, 'phptpl', 'helpers');
      $helperNamespace = '\\' . implode('\\', $nsElems);
      $view->addHelperPath($helperPath, $helperNamespace);
    }
  }
  
  public function onRoute(\ultimo\mvc\Application $application, \ultimo\mvc\Request $request) { }
  
  public function onRouted(\ultimo\mvc\Application $application, \ultimo\mvc\Request $request=null) { }
  
  public function onDispatch(\ultimo\mvc\Application $application) { }
  
  /**
   * Flushes the session.
   */
  public function onDispatched(\ultimo\mvc\Application $application) {
    $this->session->flush();
  }
  
  /**
   * Forwards the current request to an 'accessDenied' action. A controller is
   * looked for containing this action in the following order:
   * - the requested controlller
   * - the AuthController in the requested module
   * - the AuthController in the index module
   */
  public function handleAccessDenied() {
    $request = $this->application->getRequest();

    $module = $this->application->getModule('modules\\' . $request->getModule());
    if ($module === null) {
      // the requested module was not found, a 404 is a better respone
      return;
    }
    
    $controller = $module->getController($request->getController());
    if ($controller === null) {
      // the requested controller is not found, a 404 is a better response
      return;
    }
    
    // pass the denied request as parameter to the Auth controller
    $deniedRequest = clone $request;
    $request->setPostParam('deniedRequest', clone $deniedRequest);
    
    // forward the request to the requested controller, if the 'accessDenied'
    // action exists
    if ($controller->isAction('accessdenied')) {
      $request->setAction('accessdenied');
      $request->setRedispatch(true);
      return;
    }
    
    // forward the request to the AuthController in de requested module if it
    // and the 'accessDenied' action exists
    $module = $controller->getModule();
    $authController = $module->getController('Auth');
    if ($authController !== null && $authController->isAction('accessdenied')) {
      $acl = $this->getAcl($module->getNamespace());
      
      // make sure the new request is allowed, otherwise this will go into an
      // infinite loop
      if ($acl === null || $acl->isAllowed($this->getUser()->getRole(), 'auth.accessdenied')) {
        $request->setAction('accessdenied');
        $request->setController('Auth');
        $request->setRedispatch(true);
        return;
      } else {
        // notice the developers about this undesired situation
        trigger_error("Access denied to {$module->getNamespace()}\auth::accessdenied", E_USER_NOTICE);
      }
    }
    
    // forward the request to the AuthController in the index module if it and
    // the 'accessdenied' action exists
    $indexModule = $this->application->getGeneralModule();
    $authController = $indexModule->getController('Auth');
    if ($authController !== null && $authController->isAction('accessdenied')) {
      $acl = $this->getAcl($indexModule->getNamespace());
      
      // make sure the new request is allowed, otherwise this will go into an
      // infinite loop
      if ($acl === null || $acl->isAllowed($this->getUser()->getRole(), 'auth.accessdenied')) {
        $request->setAction('accessdenied');
        $request->setController('Auth');
        $request->setModule($indexModule->getNamespace());
        $request->setRedispatch(true);
        return;
      } else {
        // notice the developers about this undesired situation
        trigger_error("Access denied to {$indexModule->getNamespace()}\auth::accessdenied", E_USER_NOTICE);
      }
    }
    
    // if no suitable forward could be made, throw an exception to prevent
    // further unallowed execution
    throw new \ultimo\security\mvc\exceptions\AuthorizationException('Access denied for ' . $deniedRequest->getModule() . '\\' . $deniedRequest->getController() . '::' . $deniedRequest->getAction());
  }
  
  /**
   * Performs the authorizing. The proper accesslis is fetched, and the
   * permission for the controller action is checked for the user using the
   * application.
   */
  public function onActionCall(\ultimo\mvc\Controller $controller, &$actionName) {
    $request = $controller->getApplication()->getRequest();
    
    $acl = $this->getAcl($request->getModule());
    if ($acl === null) {
      return;
    }
 
    $user = $this->getUser();
    $privilege = strtolower($request->getController()) . '.' . $request->getAction();
    
    if (!$acl->isAllowed($user->getRole(), $privilege)) {
      $this->handleAccessDenied();
      return;
    }
  }
  
  public function onActionCalled(\ultimo\mvc\Controller $controller, $actionName) { }
  
}