<?php

namespace ultimo\security\mvc;

interface User {
  /**
   * Returns the id of the user.
   * @return mixed The id of the user.
   */
  public function getId();
  
  /**
   * Retuns the role name of the user.
   * @return string The role name of the user.
   */
  public function getRole();
}