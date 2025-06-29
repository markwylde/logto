import { useLogto } from '@logto/react';
import { useState, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { splitPassword } from '../utils/zero-knowledge-password';
import { encryptWithPassword, decryptWithPassword } from '../utils/zero-knowledge-encryption';
import { clearEncryptionData } from '../utils/encryption';
import styles from './ChangePassword.module.scss';

const ChangePassword = () => {
  const { getAccessToken } = useLogto();
  const { t } = useTranslation();
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    
    
    // Clear previous messages
    setMessage(null);
    
    // Validate passwords match
    if (newPassword !== confirmPassword) {
      setMessage({ type: 'error', text: 'New passwords do not match' });
      return;
    }
    
    setLoading(true);
    
    try {
      const accessToken = await getAccessToken();
      if (!accessToken) {
        throw new Error('Not authenticated');
      }
      
      // Split passwords for zero-knowledge encryption
      const { serverPassword: oldServerPassword, clientPassword: oldClientPassword } = await splitPassword(oldPassword);
      
      const { serverPassword: newServerPassword, clientPassword: newClientPassword } = await splitPassword(newPassword);
      
      // Get current encrypted secret
      const profileResponse = await fetch('http://localhost:3001/api/my-account/password/profile', {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      });
      
      if (!profileResponse.ok) {
        throw new Error('Failed to fetch profile');
      }
      
      const { encryptedSecret } = await profileResponse.json();
      
      let newEncryptedSecret;
      if (encryptedSecret) {
        // Decrypt and re-encrypt the secret
        try {
          const decryptedSecret = await decryptWithPassword(encryptedSecret, oldClientPassword);
          newEncryptedSecret = await encryptWithPassword(decryptedSecret, newClientPassword);
        } catch (error) {
          throw new Error('Incorrect current password');
        }
      } else {
      }
      
      // Change password
        oldPassword: '***' + oldServerPassword.slice(-4),
        newPassword: '***' + newServerPassword.slice(-4),
        hasEncryptedSecret: !!newEncryptedSecret
      });
      
      const changeResponse = await fetch('http://localhost:3001/api/my-account/password', {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          oldPassword: oldServerPassword,
          newPassword: newServerPassword,
          ...(newEncryptedSecret && { encryptedSecret: newEncryptedSecret })
        })
      });
      
      
      if (!changeResponse.ok) {
        const error = await changeResponse.json();
        throw new Error(error.message || 'Failed to change password');
      }
      
      setMessage({ type: 'success', text: 'Password changed successfully!' });
      
      // Clear encryption data since keys are now invalid
      clearEncryptionData();
      
      // Clear form
      setOldPassword('');
      setNewPassword('');
      setConfirmPassword('');
      
    } catch (error) {
      setMessage({ 
        type: 'error', 
        text: error instanceof Error ? error.message : 'Failed to change password' 
      });
    } finally {
      setLoading(false);
    }
  }, [oldPassword, newPassword, confirmPassword, getAccessToken]);

  return (
    <div className={styles.container}>
      <h1>Change Password</h1>
      <p className={styles.description}>
        Enter your current password and choose a new password for your account.
      </p>
      
      <div className={styles.notification}>
        Your password change will automatically re-encrypt your zero-knowledge secret with the new password.
      </div>
      
      <form onSubmit={handleSubmit} className={styles.form}>
        <div className={styles.formGroup}>
          <label htmlFor="oldPassword">Current Password</label>
          <input
            type="password"
            id="oldPassword"
            value={oldPassword}
            onChange={(e) => setOldPassword(e.target.value)}
            required
            disabled={loading}
          />
        </div>
        
        <div className={styles.formGroup}>
          <label htmlFor="newPassword">New Password</label>
          <input
            type="password"
            id="newPassword"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
            disabled={loading}
          />
        </div>
        
        <div className={styles.formGroup}>
          <label htmlFor="confirmPassword">Confirm New Password</label>
          <input
            type="password"
            id="confirmPassword"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
            disabled={loading}
          />
        </div>
        
        <button type="submit" disabled={loading} className={styles.submitButton}>
          {loading ? 'Changing...' : 'Change Password'}
        </button>
        
        {message && (
          <div className={`${styles.message} ${styles[message.type]}`}>
            {message.text}
          </div>
        )}
      </form>
    </div>
  );
};

export default ChangePassword;