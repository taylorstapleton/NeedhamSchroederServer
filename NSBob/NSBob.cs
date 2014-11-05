using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace NSBob
{
    class NSBob
    {

        static void Main(string[] args)
        {
            bool useCBC = true;
            // itialization vector
            byte[] IV = new byte[] { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7 };
            // kbob
            byte[] key = new byte[] { 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7 };
            // listen for alices first message
            string reponse = StartListening(IV, key, 11000, useCBC);
            Console.WriteLine("Bob repsonds to Alice with Nb encrypted with bobs key");

            string response2 = StartListening(IV, key, 11001, useCBC);
            Console.WriteLine("Bob responds with nonce2 - 1, and a nonce3, both encrypted by the shared key");

            string response3 = StartListening(IV, key, 11002, useCBC);

        }

        /// <summary>
        /// performs the socket communication. sends one message, recieves one message.
        /// </summary>
        /// <param name="toSend"></param>
        /// <returns></returns>
        public static string StartListening(byte[] IV, byte[] key, int port, bool useCBC)
        {

            string data = null;
            string toReturn = null;

            // Data buffer for incoming data.
            byte[] bytes = new Byte[1024];

            byte[] nonceBob = new byte[64];

            IPAddress addr = IPAddress.Loopback;

            //socket stuff
            IPEndPoint localEndPoint = new IPEndPoint(addr, port);

            // Create a TCP/IP socket.
            Socket listener = new Socket(AddressFamily.InterNetwork,
                SocketType.Stream, ProtocolType.Tcp);

            // Bind the socket to the local endpoint and 
            // listen for incoming connections.
            try
            {
                listener.Bind(localEndPoint);
                listener.Listen(10);

                // Program is suspended while waiting for an incoming connection.
                Socket handler = listener.Accept();
                data = null;

                // An incoming connection needs to be processed.
                while (true)
                {
                    bytes = new byte[1024];
                    int bytesRec = handler.Receive(bytes);
                    //data += Encoding.ASCII.GetString(bytes, 0, bytesRec);
                    data += getString(bytes);
                    if (data.IndexOf("<EOF>") > -1)
                    {
                        data = data.Substring(0, data.IndexOf("<EOF>"));
                        break;
                    }
                }

                toReturn = data;

                string toSend;

                int count = 0;

                //what type of message did we recieve
                switch(toReturn)
                {
                    case "I want to talk":
                        Random rnd = new Random();
                        rnd.NextBytes(nonceBob);
                        nonceBob = getBytes("1111111111111111");
                        toSend = encryptMessage(key, IV, nonceBob, useCBC);
                        break;
                    default:
                        if(count == 0)
                        {
                            count++;
                            // split our response on the delimeter
                            string[] splitString = toReturn.Split(new string[] { "987654321" }, StringSplitOptions.None);

                            // decrypt the ticket to bob
                            string decryptedTicket = Decrypt(splitString[0].Substring(0,splitString[0].Length-2), key, IV, useCBC);

                            // split the ticket on delimeter
                            string[] splitTicket = decryptedTicket.Split(new string[] { "987654321" }, StringSplitOptions.None);

                            string sharedKey = splitTicket[0];

                            //find the original nonce in the message
                            string originalNonce = splitTicket[1].Substring(0, splitTicket[1].Length - 3);

                            // decrypt N2
                            string nonce2 = Decrypt(splitString[1], getBytes(sharedKey), IV, useCBC);

                            Int64 temp;

                            Int64.TryParse(nonce2, out temp);

                            // subtract one from the nonce
                            string nonce2Minus = (temp - 1).ToString("D32");

                            // get an N3
                            string nonce3 = NextInt64().ToString("D32");

                            // send back this info to alice
                            toSend = encryptMessage(getBytes(sharedKey), IV, getBytes(nonce2Minus + nonce3), useCBC);

                        }
                        else if(count == 1)
                        {
                            return "finished";
                        }
                        else
                        {
                            toSend = null;
                        }
                        
                        break;

                }
                
                //handler.Send(Encoding.ASCII.GetBytes(toSend + "<EOF>"));
                handler.Send(getBytes(toSend + "<EOF>"));
                handler.Shutdown(SocketShutdown.Both);
                handler.Close();


            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }

            return data;
        }

        // encyrpts a message with the given key
        public static string encryptMessage(byte[] key, byte[] IV, byte[] message, bool useCBC)
        {
            byte[] keyBytes = key; // UTF8Encoding.UTF8.GetBytes(key);
            byte[] messageBytes = message;   //UTF8Encoding.UTF8.GetBytes(message);
            byte[] ivBytes = IV; // UTF8Encoding.UTF8.GetBytes(IV);

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Key = keyBytes;
            tdes.IV = ivBytes;
            tdes.Mode = CipherMode.CBC;
            tdes.Padding = PaddingMode.Zeros;

            ICryptoTransform encryptor = tdes.CreateEncryptor();

            byte[] encResult = encryptor.TransformFinalBlock(messageBytes, 0, messageBytes.Length);

            tdes.Clear();

            string toReturn = getString(encResult);
            byte[] test = getBytes(toReturn);
            return toReturn;
            
        }

        public static string getString(byte[] bytes)
        {
            char[] chars = new char[bytes.Length / sizeof(char)];
            System.Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
            return new string(chars);
        }

        public static byte[] getBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        public static string Decrypt(string cipherBlock, byte[] key, byte[] IV, bool useCBC)
        {
            byte[] toEncryptArray = getBytes(cipherBlock);

            // Set the secret key for the tripleDES algorithm
            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Key = key;
            tdes.IV = IV;
            if (useCBC)
            {
                tdes.Mode = CipherMode.CBC;
            }
            else
            {
                tdes.Mode = CipherMode.ECB;
            }
            tdes.Padding = PaddingMode.Zeros;

            ICryptoTransform cTransform = tdes.CreateDecryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
            tdes.Clear();

            // Return the Clear decrypted TEXT
            return getString(resultArray);
        }

        public static Int64 NextInt64()
        {
            Random rnd = new Random();
            var buffer = new byte[sizeof(Int64)];
            rnd.NextBytes(buffer);
            return BitConverter.ToInt64(buffer, 0);
        }
    }
}
