package tigase.db.jdbc;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;

import tigase.auth.AuthRepositoryAware;
import tigase.auth.DomainAware;
import tigase.auth.callbacks.VerifyPasswordCallback;
import tigase.db.AuthRepository;
import tigase.db.RepositoryFactory;
import tigase.util.Base64;
import tigase.xmpp.BareJID;

public class DrupalSaslCallbackHandler implements CallbackHandler, AuthRepositoryAware, DomainAware {
	private Map<String, Object> options = null;
	private String inputData;
	private BareJID jid = null;
	private String         domain;
	private DrupalUIDAuth repo;
	
	private static final Logger log = Logger.getLogger(DrupalSaslCallbackHandler.class.getName());
	
	//~--- constructors -------------------------------------------------------

	public DrupalSaslCallbackHandler(final Map<String, Object> options, DrupalUIDAuth repo) {
		this.repo = repo;
		this.options = options;
		this.domain = (String) options.get(AuthRepository.REALM_KEY);
		
		String data_str = (String) options.get(AuthRepository.DATA_KEY);
		try {
			inputData = ((data_str != null) ? new String( Base64.decode(data_str) , "Cp1252" ) : "");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	//~--- methods ------------------------------------------------------------

	// Implementation of javax.security.auth.callback.CallbackHandler

	/**
	 * Describe <code>handle</code> method here.
	 *
	 * @param callbacks a <code>Callback[]</code> value
	 * @exception IOException if an error occurs
	 * @exception UnsupportedCallbackException if an error occurs
	 */
	@Override
	public void handle(final Callback[] callbacks)
			throws IOException, UnsupportedCallbackException {

		for (int i = 0; i < callbacks.length; i++) {
			//if (log.isLoggable(Level.FINEST)) {
				log.finest("Callback: "+ callbacks[i].getClass().getSimpleName());
			//}

			if (callbacks[i] instanceof RealmCallback) {
				RealmCallback rc = (RealmCallback) callbacks[i];
				String realm = domain;//(String) options.get(AuthRepository.REALM_KEY);

				if (realm != null) {
					rc.setText(realm);
					if (jid.getLocalpart() == null ) {
						jid = BareJID.bareJIDInstanceNS( jid.toString() , realm);
						options.put(AuthRepository.USER_ID_KEY, jid);
					}
				}        // end of if (realm == null)

				if (log.isLoggable(Level.FINEST)) {
					log.finest("RealmCallback: " + realm);
				}
			} else if (callbacks[i] instanceof NameCallback) {
					NameCallback nc = (NameCallback) callbacks[i];
					String user_name = nc.getName();

					if (user_name == null) {
						user_name = nc.getDefaultName();
					}      // end of if (name == null)

					jid = BareJID.bareJIDInstanceNS(user_name, domain);
					
					log.info("NameCallback for JID: " + jid);
					/*if (jid.getLocalpart() == null ) {
						String[] elements = inputData.split("\0");
						user_name = elements[0];
						log.log(Level.FINEST, "NameCallback JID: " + elements[0] + "/" + elements[1]);
						jid = BareJID.bareJIDInstanceNS(user_name);
					}*/

					options.put(AuthRepository.USER_ID_KEY, jid);
					nc.setName(user_name);

					if (log.isLoggable(Level.FINEST)) {
						log.finest("NameCallback: " + user_name);
					}
			} else if (callbacks[i] instanceof PasswordCallback) {
				PasswordCallback pc = (PasswordCallback) callbacks[i];

				try {
					String passwd;
					
					if (inputData.contains("volatil|") ) {
						passwd = repo.getValidToken(jid, inputData);
					} else {
						passwd = repo.getPassword(jid);
					}
				    
					pc.setPassword(passwd.toCharArray());
					if (log.isLoggable(Level.FINEST)) {
						log.log(Level.FINEST, "PasswordCallback: {0}", "******");
					}
				} catch (Exception e) {
					throw new IOException("Password retrieving problem.", e);
				}    // end of try-catch
			} else if (callbacks[i] instanceof VerifyPasswordCallback) {
				VerifyPasswordCallback pc     = (VerifyPasswordCallback) callbacks[i];
				String                 passwd = new String(pc.getPassword());

				try {
					Map<String, Object> map = new HashMap<String, Object>();

					map.put(AuthRepository.PROTOCOL_KEY, AuthRepository.PROTOCOL_VAL_NONSASL);
					map.put(AuthRepository.USER_ID_KEY, jid);
					map.put(AuthRepository.PASSWORD_KEY, passwd);
					map.put(AuthRepository.REALM_KEY, jid.getDomain());
					map.put(AuthRepository.SERVER_NAME_KEY, jid.getDomain());
					pc.setVerified( repo.otherAuth(map) );
					if (log.isLoggable(Level.FINEST)) {
						log.log(Level.FINEST, "VerifyPasswordCallback: {0}", "******");
					}
					
				} catch (Exception e) {
					pc.setVerified(false);

					throw new IOException("Password verification problem.", e);
				}
			} else if (callbacks[i] instanceof AuthorizeCallback) {
				AuthorizeCallback authCallback = ((AuthorizeCallback) callbacks[i]);
				String authenId = authCallback.getAuthenticationID();
				String authorId = authCallback.getAuthorizationID();

				//if (log.isLoggable(Level.FINEST)) {
					log.finest("AuthorizeCallback: authenId: "+ authenId);
					log.finest("AuthorizeCallback: authorId: "+ authorId);
				//}

				if (authenId.equals(authorId) || authorId.equals(authenId + "@" + domain)) {
					authCallback.setAuthorized(true);
					try {
						RepositoryFactory.getUserRepository(null, null, null);
					} catch (Exception e) {
						log.log(Level.WARNING, "USER REPO init error: ", e);

						throw new UnsupportedCallbackException(callbacks[i], "User Repo exception.");
					}  
				}
			} else {
				throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
			}
					
		}
	}

	//~--- set methods ----------------------------------------------------------

	/**
	 * Method description
	 *
	 *
	 * @param repo
	 */
	@Override
	public void setAuthRepository(AuthRepository repo) {
		this.repo = (DrupalUIDAuth)repo;
	}

	/**
	 * Method description
	 *
	 *
	 * @param domain
	 */
	@Override
	public void setDomain(String domain) {
		this.domain = domain;
	}
}