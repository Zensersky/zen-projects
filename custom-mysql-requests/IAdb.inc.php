<?php
class IA_MySql {
  private static $instance;
  public $connection;

  private $dbservername = "localhost";
  private $dbUsername = "localuser";
  private $dbPassword = "password";
  private $dbName = "mysqldb";

 public function __construct() {}

  public static function get_instance() {
         if (!self::$instance) {
             self::$instance = new self();
         }
         return self::$instance;
     }

  public function connect() {
       if (!$this->connection) {
           $this->connection = mysqli_connect($this->dbservername, $this->dbUsername, $this->dbPassword, $this->dbName);
           mysqli_select_db($this->connection, $this->dbName);
       }
       return $this->connection;
   }
   public function __destruct() {
        if ($this->connection) {
            mysqli_close($this->connection);
        }
    }
    public function protected_var(string $variable) {
        if (!$this->connection) {
            $this->connect();
        }
        return mysqli_real_escape_string($this->connection, $variable);
    }

    public function execute_command($SQLCommand, string $types = null, $Params = null)
    {
        if (!$this->connection) {
            die("MySql execute called without a valid connection!");
        }

        $SQLStmt = mysqli_stmt_init($this->connection);
        if (!mysqli_stmt_prepare($SQLStmt, $SQLCommand)) {
            mysqli_stmt_close($SQLStmt);
            mysqli_close($this->connection);
            die("Failed preparing statement");
        }

        if (func_num_args() > 1) {
            mysqli_stmt_bind_param($SQLStmt, $types, ...$Params);
        }

        mysqli_stmt_execute($SQLStmt);

        $meta = mysqli_stmt_result_metadata($SQLStmt);
        if ($meta != null) {
            $params = array();
            $row = array();
            while ($field = mysqli_fetch_field($meta)) {
                $params[] = &$row[$field->name];
            }

            call_user_func_array(array($SQLStmt, 'bind_result'), $params);

            $rows = array();
            while (mysqli_stmt_fetch($SQLStmt)) {
                $c = array();
                foreach ($row as $key => $val) {
                    $c[$key] = $val;
                }
                $rows[] = $c;
            }

            mysqli_stmt_close($SQLStmt);

            return $rows;
        } else {
            mysqli_stmt_close($SQLStmt);
            return;
        }
    }
}

?>
