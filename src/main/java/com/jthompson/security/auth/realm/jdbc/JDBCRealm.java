package com.jthompson.security.auth.realm.jdbc;

import com.sun.appserv.connectors.internal.api.ConnectorRuntime;
import com.sun.enterprise.security.auth.digest.api.DigestAlgorithmParameter;
import com.sun.enterprise.security.auth.digest.api.Password;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.DigestRealmBase;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;
import com.sun.enterprise.security.common.Util;
import com.sun.enterprise.universal.GFBase64Encoder;
import com.sun.enterprise.util.Utility;
import com.sun.enterprise.util.i18n.StringManager;
import java.io.Reader;
import java.nio.charset.CharacterCodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.login.LoginException;
import javax.sql.DataSource;
import org.jvnet.hk2.component.Habitat;

public class JDBCRealm extends DigestRealmBase
{
  private static long LAST_UPDATE_INTERVAL = 0L;
  private static final long UPDATE_INTERVAL_MILLISECONDS = 10000L;
  public static final String AUTH_TYPE = "jdbc";
  public static final String PRE_HASHED = "HASHED";
  public static final String PARAM_DATASOURCE_JNDI = "datasource-jndi";
  public static final String PARAM_DB_USER = "db-user";
  public static final String PARAM_DB_PASSWORD = "db-password";
  public static final String PARAM_DIGEST_ALGORITHM = "digest-algorithm";
  public static final String NONE = "none";
  public static final String PARAM_ENCODING = "encoding";
  public static final String HEX = "hex";
  public static final String BASE64 = "base64";
  public static final String DEFAULT_ENCODING = "hex";
  public static final String PARAM_CHARSET = "charset";
  public static final String PARAM_USER_TABLE = "user-table";
  public static final String PARAM_USER_NAME_COLUMN = "user-name-column";
  public static final String PARAM_PASSWORD_COLUMN = "password-column";
  public static final String PARAM_GROUP_TABLE = "group-table";
  public static final String PARAM_GROUP_NAME_COLUMN = "group-name-column";
  public static final String PARAM_GROUP_TABLE_USER_NAME_COLUMN = "group-table-user-name-column";
  private static final char[] HEXADECIMAL = { '0', '1', '2', '3', 
    '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
  private Map<String, Vector<String>> groupCache;
  private Vector<String> emptyVector;
  private String passwordQuery = null;
  private String groupQuery = null;
  private MessageDigest md = null;
  private ConnectorRuntime cr;

  public synchronized void init(Properties props)
    throws BadRealmException, NoSuchRealmException
  {
    super.init(props);
    String jaasCtx = props.getProperty("jaas-context");
    String dbUser = props.getProperty("db-user");
    String dbPassword = props.getProperty("db-password");
    String dsJndi = props.getProperty("datasource-jndi");
    String digestAlgorithm = props.getProperty("digest-algorithm", 
      getDefaultDigestAlgorithm());
    String encoding = props.getProperty("encoding");
    String charset = props.getProperty("charset");
    String userTable = props.getProperty("user-table");
    String userNameColumn = props.getProperty("user-name-column");
    String passwordColumn = props.getProperty("password-column");
    String groupTable = props.getProperty("group-table");
    String groupNameColumn = props.getProperty("group-name-column");
    String groupTableUserNameColumn = props.getProperty("group-table-user-name-column", userNameColumn);
    this.cr = ((ConnectorRuntime)Util.getDefaultHabitat().getByContract(ConnectorRuntime.class));

    if (jaasCtx == null) {
      String msg = sm.getString(
        "realm.missingprop", "jaas-context", "JDBCRealm");
      throw new BadRealmException(msg);
    }

    if (dsJndi == null) {
      String msg = sm.getString(
        "realm.missingprop", "datasource-jndi", "JDBCRealm");
      throw new BadRealmException(msg);
    }
    if (userTable == null) {
      String msg = sm.getString(
        "realm.missingprop", "user-table", "JDBCRealm");
      throw new BadRealmException(msg);
    }
    if (groupTable == null) {
      String msg = sm.getString(
        "realm.missingprop", "group-table", "JDBCRealm");
      throw new BadRealmException(msg);
    }
    if (userNameColumn == null) {
      String msg = sm.getString(
        "realm.missingprop", "user-name-column", "JDBCRealm");
      throw new BadRealmException(msg);
    }
    if (passwordColumn == null) {
      String msg = sm.getString(
        "realm.missingprop", "password-column", "JDBCRealm");
      throw new BadRealmException(msg);
    }
    if (groupNameColumn == null) {
      String msg = sm.getString(
        "realm.missingprop", "group-name-column", "JDBCRealm");
      throw new BadRealmException(msg);
    }

    this.passwordQuery = 
      ("SELECT " + passwordColumn + " FROM " + userTable + 
      " WHERE " + userNameColumn + " = ?");

    this.groupQuery = 
      ("SELECT " + groupNameColumn + " FROM " + groupTable + 
      " WHERE " + groupTableUserNameColumn + " = ? ");

    if (!"none".equalsIgnoreCase(digestAlgorithm)) {
      try {
        this.md = MessageDigest.getInstance(digestAlgorithm);
      } catch (NoSuchAlgorithmException e) {
        String msg = sm.getString("jdbcrealm.notsupportdigestalg", 
          digestAlgorithm);
        throw new BadRealmException(msg);
      }
    }
    if ((this.md != null) && (encoding == null)) {
      encoding = "hex";
    }

    setProperty("jaas-context", jaasCtx);
    if ((dbUser != null) && (dbPassword != null)) {
      setProperty("db-user", dbUser);
      setProperty("db-password", dbPassword);
    }
    setProperty("datasource-jndi", dsJndi);
    setProperty("digest-algorithm", digestAlgorithm);
    if (encoding != null) {
      setProperty("encoding", encoding);
    }
    if (charset != null) {
      setProperty("charset", charset);
    }

    if (_logger.isLoggable(Level.FINEST)) {
      _logger.finest("JDBCRealm : jaas-context= " + 
        jaasCtx + ", " + 
        "datasource-jndi" + " = " + dsJndi + ", " + 
        "db-user" + " = " + dbUser + ", " + 
        "digest-algorithm" + " = " + digestAlgorithm + ", " + 
        "encoding" + " = " + encoding + ", " + 
        "charset" + " = " + charset);
    }

    this.groupCache = new HashMap();
    this.emptyVector = new Vector();
  }

  public String getAuthType()
  {
    return "jdbc";
  }

  public Enumeration getGroupNames(String username)
    throws InvalidOperationException, NoSuchUserException
  {
    Vector vector = (Vector)this.groupCache.get(username);
    long currentTime = Calendar.getInstance().getTimeInMillis();

    if ((currentTime > LAST_UPDATE_INTERVAL + 10000L) || 
      (vector == null)) {
      String[] grps = findGroups(username);
      setGroupNames(username, grps);
      vector = (Vector)this.groupCache.get(username);
      LAST_UPDATE_INTERVAL = currentTime;
    }
    return vector.elements();
  }

  private void setGroupNames(String username, String[] groups) {
    Vector v = null;

    if (groups == null) {
      v = this.emptyVector;
    }
    else {
      v = new Vector(groups.length + 1);
      for (int i = 0; i < groups.length; i++) {
        v.add(groups[i]);
      }
    }

    synchronized (this) {
      this.groupCache.remove(username);
      this.groupCache.put(username, v);
    }
  }

  public String[] authenticate(String username, char[] password)
  {
    String[] groups = (String[])null;
    if (isUserValid(username, password)) {
      groups = findGroups(username);
      groups = addAssignGroups(groups);
      setGroupNames(username, groups);
    }
    return groups;
  }

  public boolean validate(String username, DigestAlgorithmParameter[] params) {
    Password pass = getPassword(username);
    if (pass == null) {
      return false;
    }
    return validate(pass, params);
  }

  private Password getPassword(String username)
  {
    Connection connection = null;
    PreparedStatement statement = null;
    ResultSet rs = null;
    boolean valid = false;
    try
    {
      connection = getConnection();
      statement = connection.prepareStatement(this.passwordQuery);
      statement.setString(1, username);
      rs = statement.executeQuery();

      if (rs.next()) {
        final String pwd = rs.getString(1);
        Object localObject2;
        if (!"HASHED".equalsIgnoreCase(getProperty("encoding")))
          return new Password()
          {
            public byte[] getValue() {
              return pwd.getBytes();
            }

            public int getType() {
              return 0;
            }
          };
        return new Password()
        {
          public byte[] getValue() {
            return pwd.getBytes();
          }

          public int getType() {
            return 1;
          }
        };
      }
    }
    catch (Exception ex) {
      _logger.log(Level.SEVERE, "jdbcrealm.invaliduser", username);
      if (_logger.isLoggable(Level.FINE))
        _logger.log(Level.FINE, "Cannot validate user", ex);
    }
    finally {
      close(connection, statement, rs); } close(connection, statement, rs);

    return null;
  }

  private boolean isUserValid(String user, char[] password)
  {
    Connection connection = null;
    PreparedStatement statement = null;
    ResultSet rs = null;
    boolean valid = false;
    try
    {
      char[] hpwd = hashPassword(password);
      connection = getConnection();
      statement = connection.prepareStatement(this.passwordQuery);
      statement.setString(1, user);
      rs = statement.executeQuery();
      if (rs.next())
      {
        Reader reader = rs.getCharacterStream(1);
        char[] pwd = new char[1024];
        int noOfChars = reader.read(pwd);

        if (noOfChars < 0) {
          noOfChars = 0;
        }
        char[] passwd = new char[noOfChars];
        System.arraycopy(pwd, 0, passwd, 0, noOfChars);
        if ("hex".equalsIgnoreCase(getProperty("encoding"))) {
          valid = true;

          for (int i = 0; i < noOfChars; i++)
            if (Character.toLowerCase(passwd[i]) != Character.toLowerCase(hpwd[i])) {
              valid = false;
              break;
            }
        }
        else {
          valid = Arrays.equals(passwd, hpwd);
        }
      }
    } catch (SQLException ex) {
      _logger.log(Level.SEVERE, "jdbcrealm.invaliduserreason", 
        new String[] { user, ex.toString() });
      if (_logger.isLoggable(Level.FINE))
        _logger.log(Level.FINE, "Cannot validate user", ex);
    }
    catch (Exception ex) {
      _logger.log(Level.SEVERE, "jdbcrealm.invaliduser", user);
      if (_logger.isLoggable(Level.FINE))
        _logger.log(Level.FINE, "Cannot validate user", ex);
    }
    finally {
      close(connection, statement, rs);
    }
    return valid;
  }

  private char[] hashPassword(char[] password) throws CharacterCodingException
  {
    byte[] bytes = (byte[])null;
    char[] result = (char[])null;
    String charSet = getProperty("charset");
    bytes = Utility.convertCharArrayToByteArray(password, charSet);

    if (this.md != null) {
      synchronized (this.md) {
        this.md.reset();
        bytes = this.md.digest(bytes);
      }
    }

    String encoding = getProperty("encoding");
    if ("hex".equalsIgnoreCase(encoding))
      result = hexEncode(bytes);
    else if ("base64".equalsIgnoreCase(encoding))
      result = base64Encode(bytes).toCharArray();
    else {
      result = Utility.convertByteArrayToCharArray(bytes, charSet);
    }
    return result;
  }

  private char[] hexEncode(byte[] bytes) {
    StringBuilder sb = new StringBuilder(2 * bytes.length);
    for (int i = 0; i < bytes.length; i++) {
      int low = bytes[i] & 0xF;
      int high = (bytes[i] & 0xF0) >> 4;
      sb.append(HEXADECIMAL[high]);
      sb.append(HEXADECIMAL[low]);
    }
    char[] result = new char[sb.length()];
    sb.getChars(0, sb.length(), result, 0);
    return result;
  }

  private String base64Encode(byte[] bytes) {
    GFBase64Encoder encoder = new GFBase64Encoder();
    return encoder.encode(bytes);
  }

  private String[] findGroups(String user)
  {
    Connection connection = null;
    PreparedStatement statement = null;
    ResultSet rs = null;
    try {
      connection = getConnection();
      statement = connection.prepareStatement(this.groupQuery);
      statement.setString(1, user);
      rs = statement.executeQuery();
      List groups = new ArrayList();
      while (rs.next()) {
        groups.add(rs.getString(1));
      }
      String[] groupArray = new String[groups.size()];
      return (String[])groups.toArray(groupArray);
    } catch (Exception ex) {
      _logger.log(Level.SEVERE, "jdbcrealm.grouperror", user);
      if (_logger.isLoggable(Level.FINE)) {
        _logger.log(Level.FINE, "Cannot load group", ex);
      }
      return null;
    } finally {
      close(connection, statement, rs);
    }
  }

  private void close(Connection conn, PreparedStatement stmt, ResultSet rs)
  {
    if (rs != null)
      try {
        rs.close();
      }
      catch (Exception localException)
      {
      }
    if (stmt != null)
      try {
        stmt.close();
      }
      catch (Exception localException1)
      {
      }
    if (conn != null)
      try {
        conn.close();
      }
      catch (Exception localException2)
      {
      }
  }

  private Connection getConnection()
    throws LoginException
  {
    String dsJndi = getProperty("datasource-jndi");
    String dbUser = getProperty("db-user");
    String dbPassword = getProperty("db-password");
    try {
      String nonTxJndiName = dsJndi + "__nontx";

      DataSource dataSource = 
        (DataSource)this.cr.lookupNonTxResource(dsJndi, false);

      Connection connection = null;
      if ((dbUser != null) && (dbPassword != null)) {
        connection = dataSource.getConnection(dbUser, dbPassword);
      }
      return dataSource.getConnection();
    }
    catch (Exception ex)
    {
      String msg = sm.getString("jdbcrealm.cantconnect", dsJndi, dbUser);
      LoginException loginEx = new LoginException(msg);
      loginEx.initCause(ex);
      throw loginEx;
    }
  }
}
