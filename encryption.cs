using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Windows.Forms;

namespace ServerMap
{
    class encryption
    {
        /// <summary>
        /// AES Encrypts a string using a specified IV and KEY, returns a base64 representation of the encruypted text.
        /// </summary>
        /// <param name="text">Text to be encrypted</param>
        /// <param name="keyText">Text of Key</param>
        /// <param name="IVText">Text of IV</param>
        /// <returns></returns>
        public static string encrypt(string text, string keyText, string IVText)
        {
            try
            {


                string ret = string.Empty;
                string key = string.Empty;
                string iv = string.Empty;

                // Create a new instance of the AesManaged 
                // class.  This generates a new key and initialization  
                // vector (IV). 
                using (AesManaged myAes = new AesManaged())
                {
                    //Generate key
                    Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(keyText, GetBytes("SALT-TEXT"));
                    myAes.Key = pdb.GetBytes(32);
                    //Generate IV
                    Rfc2898DeriveBytes pdi = new Rfc2898DeriveBytes(IVText, GetBytes("SALT-TEXT"));
                    myAes.IV = pdb.GetBytes(16);
                    // Encrypt the string to an array of bytes. 
                    byte[] encrypted = EncryptStringToBytes_Aes(text, myAes.Key, myAes.IV);

                    //Convert the aes Byte array to a string
                    ret = Convert.ToBase64String(encrypted);
                }

                return ret;
            }
            catch (Exception e)
            {
                MessageBox.Show("Operation Failed:" + Environment.NewLine + e.Message);
                return string.Empty;
            }

           
        }
        
        /// <summary>
        /// Decrypts an AES encrypted Base64 String that was encrypted using the encrypt method
        /// </summary>
        /// <param name="text">Base64 text to be decrypted</param>
        /// <param name="keyText">Key used for encryption</param>
        /// <param name="IVText">IV Text used for encryption</param>
        /// <returns></returns>
        public static string decrypt(string text, string keyText, string IVText)
        {
            try
            {
                // Create a new instance of the AesManaged 
                // class.  This generates a new key and initialization  
                // vector (IV). 
                using (AesManaged myAes = new AesManaged())
                {

                    //Generate key
                    Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(keyText, GetBytes("SALT-TEXT"));
                    myAes.Key = pdb.GetBytes(32);
                    //Generate IV
                    Rfc2898DeriveBytes pdi = new Rfc2898DeriveBytes(IVText, GetBytes("SALT-TEXT"));
                    myAes.IV = pdb.GetBytes(16);

                    //Convert the string to an aes byte array
                    byte[] encrypted = Convert.FromBase64String(text);

                    // Decrypt the bytes to a string. 
                    string ret = DecryptStringFromBytes_Aes(encrypted, myAes.Key, myAes.IV);

                    return ret;
                }

            }
            catch (Exception e)
            {
                MessageBox.Show("Operation Failed:" + Environment.NewLine + e.Message);
                return string.Empty;
            }

        }

        /// <summary>
        /// Uses AES to encrypt string into bytes.
        /// </summary>
        /// <param name="plainText">String to be encrypted</param>
        /// <param name="Key">byte array key</param>
        /// <param name="IV">byte array IV</param>
        /// <returns></returns>
        private static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments. 
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Key");
            byte[] encrypted;
            // Create an AesManaged object 
            // with the specified key and IV. 
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption. 
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }


            // Return the encrypted bytes from the memory stream. 
            return encrypted;

        }
        /// <summary>
        /// Uses AES to decrypt bytes to a string
        /// </summary>
        /// <param name="plainText">byte array to be decrypted</param>
        /// <param name="Key">byte array key</param>
        /// <param name="IV">byte array IV</param>
        /// <returns></returns>
        private static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments. 
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Key");

            // Declare the string used to hold 
            // the decrypted text. 
            string plaintext = null;

            // Create an AesManaged object 
            // with the specified key and IV. 
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption. 
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream 
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;

        }

        /// <summary>
        /// Converts a string to a byte array.
        /// </summary>
        /// <param name="str">String to be converted</param>
        /// <returns></returns>
        private static byte[] GetBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        /// <summary>
        /// Converts a byte array into a string
        /// </summary>
        /// <param name="bytes">Byte array to be converted</param>
        /// <returns></returns>
        private static string GetString(byte[] bytes)
        {
            char[] chars = new char[bytes.Length / sizeof(char)];
            System.Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
            return new string(chars);
        }

    }
}