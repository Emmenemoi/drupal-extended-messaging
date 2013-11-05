/*
 * Tigase Jabber/XMPP Server
 * Copyright (C) 2004-2012 "Artur Hefczyc" <artur.hefczyc@tigase.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. Look for COPYING file in the top folder.
 * If not, see http://www.gnu.org/licenses/.
 *
 * $Rev$
 * Last modified by $Author$
 * $Date$
 */

package tigase.db.jdbc;

//~--- non-JDK imports --------------------------------------------------------

import tigase.db.AuthRepository;
import tigase.db.AuthorizationException;
import tigase.db.DBInitException;
import tigase.db.DataRepository;
import tigase.db.RepositoryFactory;
import tigase.db.TigaseDBException;
import tigase.db.UserExistsException;
import tigase.db.UserNotFoundException;
//import tigase.db.jdbc.DrupalWPAuth;

import tigase.util.Algorithms;
import tigase.util.Base64;

import tigase.xmpp.BareJID;


//~--- JDK imports ------------------------------------------------------------

import java.math.BigDecimal;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import java.util.Map;
import java.util.TreeMap;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

//~--- classes ----------------------------------------------------------------

/**
 * Describe class DrupalWPAuth here.
 *
 *
 * Created: Sat Nov 11 22:22:04 2006
 *
 * @author <a href="mailto:artur.hefczyc@tigase.org">Artur Hefczyc</a>
 * @version $Rev$
 */
public class DrupalUIDAuth extends JDBCRepository {

	/**
	 * Comma separated list of NON-SASL authentication mechanisms. Possible
	 * mechanisms are: <code>password</code> and <code>digest</code>.
	 * <code>digest</code> mechanism can work only with
	 * <code>get-password-query</code> active and only when password are stored in
	 * plain text format in the database.
	 */
	public static final String DEF_NONSASL_MECHS_KEY = "non-sasl-mechs";

	/**
	 * Comma separated list of SASL authentication mechanisms. Possible mechanisms
	 * are all mechanisms supported by Java implementation. The most common are:
	 * <code>PLAIN</code>, <code>DIGEST-MD5</code>, <code>CRAM-MD5</code>.
	 * 
	 * "Non-PLAIN" mechanisms will work only with the
	 * <code>get-password-query</code> active and only when passwords are stored
	 * in plain text format in the database.
	 */
	public static final String DEF_SASL_MECHS_KEY = "sasl-mechs";
	
	
	
	
	/**
	 * Private logger for class instances.
	 */
	private static final Logger log = Logger.getLogger(DrupalUIDAuth.class.getName());

	/** Field description */
	public static final String DEF_NONSASL_MECHS = "password";

	/** Field description */
	public static final String DEF_SASL_MECHS = "PLAIN";
	
	/** Field description */
	private static final int TOKEN_TIMEOUT = 10; // in secs

	/** Field description */
	public static final String DRUPAL_USERS_TBL = "users";

	/** Field description */
	public static final String DRUPAL_XMPP_TBL = "rtmfpcam_peers";

	/** Field description */
	public static final String DRUPAL_XMPP_NAME_FLD = "uid";

	/** Field description */
	public static final String DRUPAL_NAME_FLD = "uid";

	/** Field description */
	public static final String DRUPAL_PASS_FLD = "pass";

	/** Field description */
	public static final String DRUPAL_STATUS_FLD = "status";

	/** Field description */
	public static final int DRUPAL_OK_STATUS_VAL = 1;

	/** Field description */
	public static final String WP_USERS_TBL = "wp_users";

	/** Field description */
	public static final String WP_NAME_FLD = "user_login";

	/** Field description */
	public static final String WP_PASS_FLD = "user_pass";

	/** Field description */
	public static final String WP_STATUS_FLD = "user_status";

	/** Field description */
	public static final int WP_OK_STATUS_VAL = 0;
	private static final String SELECT_PASSWORD_QUERY_KEY = "select-password-drupal-wp-query-key";
	private static final String SELECT_STATUS_QUERY_KEY = "select-status-drupal-wp-query-key";
	private static final String INSERT_USER_QUERY_KEY = "insert-user-drupal-wp-query-key";
	private static final String UPDATE_LAST_LOGIN_QUERY_KEY = "update-last-login-drupal-wp-query-key";
	private static final String UPDATE_LAST_ACCESS_QUERY_KEY = "update-last-access-drupal-wp-query-key";
	private static final String UPDATE_ONLINE_STATUS_QUERY_KEY = "update-online-status-drupal-wp-query-key";

	//~--- fields ---------------------------------------------------------------

	private DataRepository data_repo = null;
	private String name_fld = DRUPAL_NAME_FLD;
	private String users_tbl = DRUPAL_USERS_TBL;
	private String xmpp_name_fld = DRUPAL_XMPP_NAME_FLD;
	private String xmpp_tbl = DRUPAL_XMPP_TBL;
	private int status_val = DRUPAL_OK_STATUS_VAL;
	private String status_fld = DRUPAL_STATUS_FLD;
	private String pass_fld = DRUPAL_PASS_FLD;
	private boolean online_status = false;
	private boolean last_login = true;
	private String tempsalt = "DRUPALSALT";
	private String[] sasl_mechs = DEF_SASL_MECHS.split(",");
	private String[] nonsasl_mechs = DEF_NONSASL_MECHS.split(",");

	//~--- methods --------------------------------------------------------------

	/**
	 * Describe <code>addUser</code> method here.
	 *
	 * @param user a <code>String</code> value
	 * @param password a <code>String</code> value
	 * @exception UserExistsException if an error occurs
	 * @exception TigaseDBException if an error occurs
	 */
	@Override
	public void addUser(BareJID user, final String password)
			throws UserExistsException, TigaseDBException {
		try {
			PreparedStatement user_add_st = data_repo.getPreparedStatement(user, INSERT_USER_QUERY_KEY);

			synchronized (user_add_st) {
				user_add_st.setString(1, user.getLocalpart());
				user_add_st.setString(2, Algorithms.hexDigest("", password, "MD5"));
				user_add_st.executeUpdate();
			}
		} catch (NoSuchAlgorithmException e) {
			throw new TigaseDBException("Password encoding algorithm is not supported.", e);
		} catch (SQLException e) {
			throw new UserExistsException("Error while adding user to repository, user exists?", e);
		}
	}

	//~--- get methods ----------------------------------------------------------

	/**
	 * Method description
	 *
	 *
	 * @return
	 */
	@Override
	public String getResourceUri() {
		return data_repo.getResourceUri();
	}

	/**
	 * Method description
	 *
	 *
	 * @return
	 */
	@Override
	public long getUsersCount() {
		return -1;
	}

	/**
	 * Method description
	 *
	 *
	 * @param domain
	 *
	 * @return
	 */
	@Override
	public long getUsersCount(String domain) {
		return -1;
	}

	protected String getParamWithDef(Map<String, String> params, String key, String def) {
		if (params == null) {
			return def;
		}

		String result = params.get(key);

		if (result != null) {
			log.log(Level.CONFIG, "Custom query loaded for ''{0}'': ''{1}''", new Object[] {
					key, result });
		} else {
			result = def;
			log.log(Level.CONFIG, "Default query loaded for ''{0}'': ''{1}''", new Object[] {
					key, def });
		}

		if (result != null) {
			result = result.trim();

			if (result.isEmpty()) {
				result = null;
			}
		}

		return result;
	}
	//~--- methods --------------------------------------------------------------

	/**
	 * Describe <code>initRepository</code> method here.
	 *
	 * @param connection_str a <code>String</code> value
	 * @param params
	 * @exception DBInitException if an error occurs
	 */
	@Override
	public void initRepository(final String connection_str, Map<String, String> params)
			throws DBInitException {
		try {
			data_repo = RepositoryFactory.getDataRepository(null, connection_str, params);

			if (connection_str.contains("online_status=true")) {
				online_status = true;
			}
			
			String saltconfig = "tempsalt=";
			if (connection_str.contains(saltconfig)) {
				int i = connection_str.indexOf(saltconfig);
				if(i != -1) {
					tempsalt = connection_str.substring(i + saltconfig.length());
					int n = tempsalt.indexOf("&");
					if(n != -1) {
						tempsalt = tempsalt.substring(0, n);
					}
				} 
				log.log(Level.CONFIG, "Salt for temp passwords set to : {0}", tempsalt);
			}
			
			nonsasl_mechs = getParamWithDef(params, DEF_NONSASL_MECHS_KEY, DEF_NONSASL_MECHS).split(",");
			sasl_mechs = getParamWithDef(params, DEF_SASL_MECHS_KEY, DEF_SASL_MECHS).split(",");
			
			if (connection_str.contains("wp_mode=true")) {
				online_status = false;
				last_login = false;
				name_fld = WP_NAME_FLD;
				users_tbl = WP_USERS_TBL;
				status_val = WP_OK_STATUS_VAL;
				status_fld = WP_STATUS_FLD;
				pass_fld = WP_PASS_FLD;
				log.log(Level.INFO, "Initializing Wordpress repository: {0}", connection_str);
			} else {
				log.log(Level.INFO, "Initializing Drupal via UID repository: {0}", connection_str);
			}

			String query = "select " + pass_fld + " from " + users_tbl + " where " + name_fld + " = ? LIMIT 1";
			data_repo.initPreparedStatement(SELECT_PASSWORD_QUERY_KEY, query);
			
			query = "select " + status_fld + " from " + users_tbl + " where " + name_fld + " = ? LIMIT 1";
			data_repo.initPreparedStatement(SELECT_STATUS_QUERY_KEY, query);
			
			query = "insert into " + users_tbl + " (" + name_fld + ", " + pass_fld + ", " + status_fld
					+ ")" + " values (?, ?, " + status_val + ")";
			data_repo.initPreparedStatement(INSERT_USER_QUERY_KEY, query);
			
			query = "update " + users_tbl + " set access=?, login=? where " + name_fld + " = ? LIMIT 1";
			data_repo.initPreparedStatement(UPDATE_LAST_LOGIN_QUERY_KEY, query);

			query = "update " + users_tbl + " set access=? where " + name_fld + " = ? LIMIT 1";
			data_repo.initPreparedStatement(UPDATE_LAST_ACCESS_QUERY_KEY, query);
			
			query = "update " + xmpp_tbl + " set online_status=online_status+? where " + xmpp_name_fld
					+ " = ? LIMIT 1";
			data_repo.initPreparedStatement(UPDATE_ONLINE_STATUS_QUERY_KEY, query);
		} catch (Exception e) {
			data_repo = null;

			throw new DBInitException("Problem initializing jdbc connection: " + connection_str, e);
		}

		try {
			if (online_status) {
				Statement stmt = data_repo.createStatement(null);

				stmt.executeUpdate("update "+xmpp_tbl+" set online_status = 0;");
				stmt.close();
				stmt = null;
			}
		} catch (SQLException e) {
			if (e.getMessage().contains("'online_status'")) {
				try {
					Statement stmt = data_repo.createStatement(null);

					stmt.executeUpdate("alter table "+xmpp_tbl+" add online_status int default 0;");
					stmt.close();
					stmt = null;
				} catch (SQLException ex) {
					data_repo = null;

					throw new DBInitException("Problem initializing jdbc connection: " + connection_str, ex);
				}
			} else {
				data_repo = null;

				throw new DBInitException("Problem initializing jdbc connection: " + connection_str, e);
			}
		}
		
	}

	/**
	 * Method description
	 *
	 *
	 * @param user
	 *
	 * @throws TigaseDBException
	 * @throws UserNotFoundException
	 */
	@Override
	public void logout(BareJID user) throws UserNotFoundException, TigaseDBException {
		updateOnlineStatus(user, -1);
	}

	/**
	 * Describe <code>digestAuth</code> method here.
	 *
	 * @param user a <code>String</code> value
	 * @param digest a <code>String</code> value
	 * @param id a <code>String</code> value
	 * @param alg a <code>String</code> value
	 * @return a <code>boolean</code> value
	 * @exception UserNotFoundException if an error occurs
	 * @exception TigaseDBException if an error occurs
	 * @exception AuthorizationException if an error occurs
	 */
	@Override
	@Deprecated
	public boolean digestAuth(BareJID user, final String digest, final String id, final String alg)
			throws UserNotFoundException, TigaseDBException, AuthorizationException {
		throw new AuthorizationException("Not supported.");
	}
	
	/**
	 * Describe <code>otherAuth</code> method here.
	 *
	 * @param props a <code>Map</code> value
	 * @return a <code>boolean</code> value
	 * @exception UserNotFoundException if an error occurs
	 * @exception TigaseDBException if an error occurs
	 * @exception AuthorizationException if an error occurs
	 */
	@Override
	public boolean otherAuth(final Map<String, Object> props)
			throws UserNotFoundException, TigaseDBException, AuthorizationException {
		if (log.isLoggable(Level.FINEST)) {
			log.log(Level.FINEST, "otherAuth: {0}", props);
		}
		
		String proto = (String) props.get(PROTOCOL_KEY);

		if (proto.equals(PROTOCOL_VAL_SASL)) {
			String mech = (String) props.get(MACHANISM_KEY);

			try {
				if (mech.equals("PLAIN")) {
					boolean login_ok = saslAuth(props);

					if (login_ok) {
						BareJID user = (BareJID) props.get(USER_ID_KEY);

						// Unfortunately, unlike with plainAuth we have to check whether the user
						// is active after successful authentication as before it is completed the
						// user id is not known
						if ( !isActive(user)) {
							throw new AuthorizationException("User account has been blocked.");
						}    // end of if (!isActive(user))

						//updateLastLogin(user);
						updateLastAccess(user);
						updateOnlineStatus(user, 1);
						//RepositoryFactory.getUserRepository(null, null, null);

						if (log.isLoggable(Level.FINEST)) {
							log.log(Level.FINEST, "User authenticated: {0}", user.toString());
						}
					} else {
						if (log.isLoggable(Level.FINEST)) {
							log.finest("User NOT authenticated");
						}
					}

					return login_ok;
				}        // end of if (mech.equals("PLAIN"))
			} catch (Exception e) {
				log.log(Level.FINEST, "OTHER authentication error: ", e);
				throw new AuthorizationException("Sasl exception.", e);
			}          // end of try-catch

			throw new AuthorizationException("Mechanism is not supported: " + mech);
		}            // end of if (proto.equals(PROTOCOL_VAL_SASL))

		if (proto.equals(PROTOCOL_VAL_NONSASL)) {
			String password = (String) props.get(PASSWORD_KEY);
			BareJID user_id = (BareJID) props.get(USER_ID_KEY);
			boolean login_ok = false;
			if (password != null) {
				
				if (password.contains("volatil|") ) {
					login_ok = tokenAuth(user_id, password);
				} else {
					login_ok = plainAuth(user_id, password);
				}
			}
			String digest = (String) props.get(DIGEST_KEY);
			if (digest != null) {
				String digest_id = (String) props.get(DIGEST_ID_KEY);
				login_ok = digestAuth(user_id, digest, digest_id, "SHA");
			}
			
			if (login_ok) {
				
				try {
					RepositoryFactory.getUserRepository(null, null, null);
				} catch (Exception e) {
					if (log.isLoggable(Level.FINEST)) {
						log.log(Level.FINEST, "USER REPO init error: ", e);
					}

					throw new AuthorizationException("User Repo exception.", e);
				}  
			}
			
			return login_ok;
		} // end of if (proto.equals(PROTOCOL_VAL_SASL))

		throw new AuthorizationException("Protocol is not supported: " + proto);
	}

	/**
	 * Describe <code>plainAuth</code> method here.
	 *
	 * @param user a <code>String</code> value
	 * @param password a <code>String</code> value
	 * @return a <code>boolean</code> value
	 *
	 * @throws AuthorizationException
	 * @exception UserNotFoundException if an error occurs
	 * @exception TigaseDBException if an error occurs
	 */
	@Override
	@Deprecated
	public boolean plainAuth(BareJID user, final String password)
			throws UserNotFoundException, TigaseDBException, AuthorizationException {
		try {
			if ( !isActive(user)) {
				throw new AuthorizationException("User account has been blocked.");
			}    // end of if (!isActive(user))

			String enc_passwd = Algorithms.hexDigest("", password, "MD5");
			String db_password = getPassword(user);
			boolean login_ok = db_password.equals(enc_passwd);

			log.log(Level.INFO, "MD5 password: {0} is: " + (login_ok? "ok" : "nok"), enc_passwd);
			
			if (login_ok) {
				updateLastLogin(user);
				updateOnlineStatus(user, 1);

				if (log.isLoggable(Level.FINEST)) {
					log.log(Level.FINEST, "User authenticated: {0}", user);
				}
			} else {
				if (log.isLoggable(Level.FINEST)) {
					log.log(Level.FINEST, "User NOT authenticated: {0}", user);
				}
			}

			return login_ok;
		} catch (NoSuchAlgorithmException e) {
			throw new AuthorizationException("Password encoding algorithm is not supported.", e);
		} catch (SQLException e) {
			throw new TigaseDBException("Problem accessing repository.", e);
		}      // end of catch
	}

	// Implementation of tigase.db.AuthRepository

	/**
	 * Describe <code>queryAuth</code> method here.
	 *
	 * @param authProps a <code>Map</code> value
	 */
	@Override
	public void queryAuth(final Map<String, Object> authProps) {
		String protocol = (String) authProps.get(PROTOCOL_KEY);

		if (protocol.equals(PROTOCOL_VAL_NONSASL)) {
			authProps.put(RESULT_KEY, nonsasl_mechs);
		}    // end of if (protocol.equals(PROTOCOL_VAL_NONSASL))

		if (protocol.equals(PROTOCOL_VAL_SASL)) {
			authProps.put(RESULT_KEY, sasl_mechs);
		}    // end of if (protocol.equals(PROTOCOL_VAL_NONSASL))
		
		if (log.isLoggable(Level.FINEST)) {
			log.log(Level.FINEST, "Query Auth for props: {0}", authProps);
		}
	}

	/**
	 * Describe <code>removeUser</code> method here.
	 *
	 * @param user a <code>String</code> value
	 * @exception UserNotFoundException if an error occurs
	 * @exception TigaseDBException if an error occurs
	 */
	@Override
	public void removeUser(BareJID user) throws UserNotFoundException, TigaseDBException {
		throw new TigaseDBException("Removing user is not supported.");
	}

	/**
	 * Describe <code>updatePassword</code> method here.
	 *
	 * @param user a <code>String</code> value
	 * @param password a <code>String</code> value
	 * @exception TigaseDBException if an error occurs
	 * @throws UserNotFoundException
	 */
	@Override
	public void updatePassword(BareJID user, final String password)
			throws UserNotFoundException, TigaseDBException {
		throw new TigaseDBException("Updating user password is not supported.");
	}

	//~--- get methods ----------------------------------------------------------

//private long getMaxUID() throws SQLException {
//  ResultSet rs = null;
//
//  try {
//    synchronized (max_uid_st) {
//      rs = max_uid_st.executeQuery();
//
//      if (rs.next()) {
//        BigDecimal max_uid = rs.getBigDecimal(1);
//
//        // System.out.println("MAX UID = " + max_uid.longValue());
//        return max_uid.longValue();
//      } else {
//
//        // System.out.println("MAX UID = -1!!!!");
//        return -1;
//      }    // end of else
//    }
//  } finally {
//    release(null, rs);
//  }
//}
	public String getPassword(BareJID user) throws SQLException, UserNotFoundException {
		ResultSet rs = null;

		try {
			String userID = user.getLocalpart() == null ? user.toString() : user.getLocalpart() ;
			PreparedStatement pass_st = data_repo.getPreparedStatement(user, SELECT_PASSWORD_QUERY_KEY);

			synchronized (pass_st) {
				log.log(Level.INFO, "User uid: {0}", userID);

				pass_st.setString(1, userID );
				rs = pass_st.executeQuery();

				if (rs.next()) {
					String passwd = rs.getString(1);
					log.log(Level.INFO, "PasswordCallback: {0}", passwd);
					return passwd;
				} else {
					throw new UserNotFoundException("User does not exist: " + user + " requested UID: " + userID );
				}    // end of if (isnext) else
			}
		} finally {
			data_repo.release(null, rs);
		}
	}
	public String getValidToken(BareJID user, String tempPwd) throws UserNotFoundException {
	      String[] elements = tempPwd.split("\\|");
	      if (elements.length < 4)
	    	  throw new UserNotFoundException("User does not exist: " + user + " requested UID: " + user.getLocalpart());
	      
	      //String signature = elements[0]; // should be "volatil"
	      String login = elements[1];
	      String timestamp = elements[2];
	      String submittedToken = elements[3];
	      /*
	      if( ( System.currentTimeMillis()/1000 - Integer.valueOf(timestamp).intValue() ) > TOKEN_TIMEOUT) {//timeout
	    	if (log.isLoggable(Level.FINEST)) {
				log.log(Level.FINEST, "Token timeout");
			}
	        return "";
	      }
	      */
	      try {
	    	    log.log(Level.INFO, "Check token submitted: {0}", submittedToken);
	    	  	String token = Algorithms.hexDigest("", login+timestamp+tempsalt, "SHA-256");
	    	  	log.log(Level.INFO, "Check token: {0}", token);
				if ( !token.equals(submittedToken) ) {//oneshot password
					if (log.isLoggable(Level.FINEST)) {
						log.log(Level.FINEST, "Bad token");
					}
					return "";
				}
				return "volatil|"+login+"|"+timestamp+"|"+token;
	      } catch (NoSuchAlgorithmException e) {	    	    
				log.log(Level.WARNING, "NO Algorythm:");
				e.printStackTrace();
		  }	
	      return "";
	}
	
	public boolean tokenAuth(BareJID user, String tempPwd) throws UserNotFoundException, AuthorizationException, TigaseDBException {
		try {
			if ( !isActive(user)) {
				throw new AuthorizationException("User account has been blocked.");
			}
	
			boolean login_ok = getValidToken(user, tempPwd).equals(tempPwd);
			if (login_ok) {
					updateLastAccess(user);
					updateOnlineStatus(user, 1);					
			}
				
			return login_ok;
		} catch (SQLException e) {
			throw new TigaseDBException("Problem accessing repository.", e);
		}
	}

	private boolean isActive(BareJID user) throws SQLException, UserNotFoundException {
		ResultSet rs = null;

		try {
			String userID = user.getLocalpart() == null ? user.toString() : user.getLocalpart() ;
			PreparedStatement status_st = data_repo.getPreparedStatement(user, SELECT_STATUS_QUERY_KEY);

			synchronized (status_st) {
				status_st.setString(1, userID);
				rs = status_st.executeQuery();

				if (rs.next()) {
					return (rs.getInt(1) == status_val);
				} else {
					throw new UserNotFoundException("User does not exist: " + userID );
				}    // end of if (isnext) else
			}
		} finally {
			data_repo.release(null, rs);
		}
	}

	//~--- methods --------------------------------------------------------------

	private boolean saslAuth(final Map<String, Object> props) throws AuthorizationException {
		try {
			SaslServer ss = (SaslServer) props.get("SaslServer");
			String data_str = (String) props.get(DATA_KEY);
			byte[] in_data = ((data_str != null) ? Base64.decode(data_str) : new byte[0]);
			String data = new String( in_data , "Cp1252" );
			if (!data.contains("volatil|")) {
				MessageDigest md = MessageDigest.getInstance("MD5");
				byte[] thedigest = md.digest(in_data);
				data = new String( thedigest , "Cp1252" );
				//sasl_props.put( SaslPLAIN.ENCRYPTION_KEY, SaslPLAIN.ENCRYPTION_MD5);
			}
			
			if (ss == null) {
				Map<String, String> sasl_props = new TreeMap<String, String>();
				sasl_props.put(Sasl.QOP, "auth");	
				
				
				ss = Sasl.createSaslServer((String) props.get(MACHANISM_KEY), "xmpp",
						(String) props.get(SERVER_NAME_KEY), sasl_props, new DrupalSaslCallbackHandler(props, this));
				props.put("SaslServer", ss);
			}    // end of if (ss == null)

			
			
			log.log(Level.INFO, "SASL: Evaluate Token: {0}", data );
			byte[] challenge = ss.evaluateResponse(in_data);

			if (log.isLoggable(Level.FINEST)) {
				log.log(Level.FINEST, "challenge: {0}",
						((challenge != null) ? new String(challenge) : "null"));
			}

			String challenge_str = (((challenge != null) && (challenge.length > 0))
				? Base64.encode(challenge) : null);

			props.put(RESULT_KEY, challenge_str);

			if (ss.isComplete()) {
				return true;
			} else {
				return false;
			}    // end of if (ss.isComplete()) else
		} catch (SaslException e) {
			if (log.isLoggable(Level.FINEST)) {
				log.finest("SASL authentication error: "+ e);
			}

			throw new AuthorizationException("Sasl exception.", e);
		} catch (Exception e) {
			if (log.isLoggable(Level.FINEST)) {
				log.finest("SASL authentication error: "+ e);
			}

			throw new AuthorizationException("Sasl exception.", e);
		}      // end of try-catch
	}

	private void updateLastLogin(BareJID user) throws TigaseDBException {
		if (last_login) {
			try {
				PreparedStatement update_last_login_st =
					data_repo.getPreparedStatement(user, UPDATE_LAST_LOGIN_QUERY_KEY);

				synchronized (update_last_login_st) {
					BigDecimal bd = new BigDecimal((System.currentTimeMillis() / 1000));

					update_last_login_st.setBigDecimal(1, bd);
					update_last_login_st.setBigDecimal(2, bd);
					update_last_login_st.setString(3, user.getLocalpart());
					update_last_login_st.executeUpdate();
				}
			} catch (SQLException e) {
				throw new TigaseDBException("Error accessing repository.", e);
			}    // end of try-catch
		}
	}

	private void updateLastAccess(BareJID user) throws TigaseDBException {
		if (last_login) {
			try {
				PreparedStatement update_last_login_st =
					data_repo.getPreparedStatement(user, UPDATE_LAST_ACCESS_QUERY_KEY);

				synchronized (update_last_login_st) {
					BigDecimal bd = new BigDecimal((System.currentTimeMillis() / 1000));

					update_last_login_st.setBigDecimal(1, bd);
					update_last_login_st.setString(2, user.getLocalpart());
					update_last_login_st.executeUpdate();
				}
			} catch (SQLException e) {
				throw new TigaseDBException("Error accessing repository.", e);
			}    // end of try-catch
		}
	}
	
	private void updateOnlineStatus(BareJID user, int status) throws TigaseDBException {
		if (online_status) {
			try {
				PreparedStatement update_online_status =
					data_repo.getPreparedStatement(user, UPDATE_ONLINE_STATUS_QUERY_KEY);

				synchronized (update_online_status) {
					update_online_status.setInt(1, status);
					update_online_status.setString(2, user.getLocalpart());
					update_online_status.executeUpdate();
				}
				log.info("User online status for "+user.toString()+": " + status);
			} catch (SQLException e) {
				throw new TigaseDBException("Error accessing repository for online status update.", e);
			}    // end of try-catch
		}
	}
	
}    // DrupalWPAuth


//~ Formatted in Sun Code Convention


//~ Formatted by Jindent --- http://www.jindent.com