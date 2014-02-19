<?php

namespace ultimo\security\mvc;

interface AuthorizedModule {
  /**
   * Returns the accesslist of the module. It must contain the module roles, 
   * module privileges and a mapping between applicatoin roles and module roles.
   * @return Acl The accesslist of the module.
   */
  public function getAcl();
}