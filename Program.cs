using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Configuration;
using System.Data;
using System.Web;

namespace SHA_256_Encryption
{
    class Program
    {
        static void Main(string[] args)
        {

        }

        private static void CheckPassowrd(string Year)
        {

            string SqlConnSettings = ConfigurationManager.AppSettings["Enter your Database Key from the webconfig"]; // This will pull the database information from the app.config 
            SqlConnSettings = SqlConnSettings.Replace("",""); // If you have multiple databases and you need to replace the names
            SqlConnection SqlConn = new SqlConnection(SqlConnSettings); // Establish a new Database connection
            SqlCommand SqlComm = new SqlCommand(); // Establish a new Database Sql Command
            SqlComm.CommandText = "SELECT top 20 userid, UserName, Password, SID FROM [Your table from the database] where isEncrypted=0 or isEncrypted is null"; // Input your SQL here 
            SqlComm.CommandType = CommandType.Text; // Define the sql command type
            SqlComm.Connection = SqlConn; // Tying the connection to the sql command

            SqlConn.Open(); // Open the databse connection

            SqlDataReader objReader = SqlComm.ExecuteReader(); // Initializing objReader

            string salt = ""; 

            while (objReader.Read())
            {
                salt = objReader["SID"].ToString(); // Setting up the salt to the SID that is stored in the database
                string encryptionPassword = ""; 
                string EncPassword = "";

                try
                {
                    if (objReader["SID"] != DBNull.Value)
                    {
                        salt = objReader["SID"].ToString();
                    }
                    else
                    {
                        salt = new Guid().ToString();
                    }

                    encryptionPassword = ConfigurationManager.AppSettings["ENCKEY"] + objReader["UserName"].ToString(); 
                    EncPassword = EncryptText(objReader["Password"].ToString(), encryptionPassword, salt);

                    //update db with password and new salt
                    Console.WriteLine($"username: {objReader["UserName"].ToString()},   password:{objReader["password"].ToString()},    encrypted: {EncPassword}");

                    string updateString = $"update `Your table name from the database` set password='{EncPassword}', salt='{salt}', isEncrypted=1 where userid='{objReader["userid"].ToString()}'";
                    Console.WriteLine(updateString);
                    Console.WriteLine();
                }
                catch (Exception e)
                {
                    salt = "";
                    encryptionPassword = "";

                }
            }
            objReader.Close();

        }

        public static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes, byte[] saltBytes)
        {
            byte[] encryptedBytes = null;

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    AES.Padding = PaddingMode.PKCS7;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }

                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }

        public static string EncryptText(string input, string password, string salt)
        {
            //Get the bytes of each string that is being passed
            byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(input);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);

            // Hash the password with SHA256
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesEncrypted = AES_Encrypt(bytesToBeEncrypted, passwordBytes, saltBytes);

            string result = Convert.ToBase64String(bytesEncrypted);

            return result;

        }
    }
}
