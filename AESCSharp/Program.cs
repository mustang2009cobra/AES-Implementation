using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AESCSharp
{

    class Program
    {
        public static bool debug;

        public static void Debug(String message)
        {
            if (Program.debug)
            {
                Console.WriteLine(message);
            }
        }

        static void Main(string[] args)
        {
            Program.debug = false;
            if(args.Length < 3){
                Console.WriteLine("You must provide the filepaths for the plaintext and the cipher key.");
                Console.ReadLine();
                return;
            }

            if (args.Length == 4)
            {
                if (args[3] == "debug")
                {
                    Program.debug = true;
                }
            }
        
            String action = args[0];
        
            String plaintextPath = args[1];
            String keyPath = args[2];
            byte[,] input = null;
        
            //Read plaintext from file
            try{
                System.IO.StreamReader plainScan = new System.IO.StreamReader(plaintextPath);
                String plaintext = plainScan.ReadLine();
                if(plaintext.Length != 32){
                    throw new Exception("Plaintext block size must be 128 bits");
                }

                input = new byte[4,4];
                int currPos = 0;

                //Parse plaintext and put it in the array
                for(int j = 0; j < input.GetLength(0); j++){ //J goes on the outside because we fill columns first, then rows
                    for(int i = 0; i < input.GetLength(0); i++){ //I goes on the inside because we fill columns first, then rows\
                        String currentVal = plaintext.Substring(currPos, 2);
                        input[i,j] = Byte.Parse(currentVal, System.Globalization.NumberStyles.HexNumber);
                        currPos += 2;
                    }
                }
            }catch(Exception e){
                Console.WriteLine("File reading exception: " + e.Message);
                Console.ReadLine();
                return;
            }
        
            byte[,] key = null;
            int keylength = -1;
            try{
                System.IO.StreamReader keyScan = new System.IO.StreamReader(keyPath);
                String keytext = keyScan.ReadLine();
                if(keytext.Length == 32){
                    key = new byte[4,4]; //128 bit key is a 4x4 
                    keylength = 128;
                }
                else if(keytext.Length == 48){
                    key = new byte[4,6]; //196 bit key is a 4x6 array
                    keylength = 192;
                }
                else if(keytext.Length == 64){
                    key = new byte[4,8]; //256 bit key is a 4x8 array
                    keylength = 256;
                }
                else{
                    throw new Exception("Invalid key length. Accepted lengths are 128, 192, and 256 bits");
                }

                //Parse keytext and put it in the array
                int currPos = 0;
                for(int j = 0; j < key.GetLength(1); j++){ //J goes on the outside because we fill columns first, then rows
                    for(int i = 0; i < key.GetLength(0); i++){ //I goes on the inside because we fill columns first, then rows
                        key[i, j] = byte.Parse(keytext.Substring(currPos, 2), System.Globalization.NumberStyles.HexNumber);
                        currPos += 2;
                    } 
                }
            }catch(Exception e){
                Console.WriteLine("Key reading exception: " + e.Message);
            }
        
            Program.printArray(input, "Initial plaintext", true);
            Program.printArray(key, "Initial key", true);
        
            if(action == "encrypt"){
                //Get the keyschedule from key
                KeySchedule ks = new KeySchedule(key);
                byte[,] schedule = ks.getSchedule();

                Program.printSchedule(schedule, "Generated schedule");

                //Create cipher and encrypt data
                Cipher cipher = new Cipher(input, schedule, keylength);
                byte[,] output = cipher.encrypt();
            
                Program.printArray(output, "Final ciphertext array", true); //DEBUG

                //Write out to a file
            }
            else if(action == "decrypt"){
                //Get the keyschedule from the key
                KeySchedule ks = new KeySchedule(key);
                byte[,] schedule = ks.getSchedule();
            
                //Create inverse cipher and decrypt data
                InverseCipher invCipher = new InverseCipher(input, schedule, keylength);
                byte[,] output = invCipher.decrypt();
            
                Program.printArray(output, "Final decrypted plaintext", true); //DEBUG
            
                //Write out to a file
            }
            else{
                Console.WriteLine("Unsupported action");
            }
            Console.ReadLine();
        }

        /**
         * Copies the 4x4 in array to the state array
         * @param in The 4x4 input array
         * @return  The 4x4 state array
         */
        public static byte[,] copyDoubleArray(byte[,] input){
            byte[,] state = new byte[4, 4];
            for(int i = 0; i < input.GetLength(0); i++){ //i = row
                for(int j = 0; j < input.GetLength(0); j++){ //j = column
                    state[i,j] = input[i,j];
                }
            }
            return state;
        }
    
        /**
         * Debug method that prints the values of a double array
         * 
         * @param array The double array to print
         */
        public static void printArray(byte[,] array, String message, bool forcePrint = false){
            if (Program.debug || forcePrint)
            {
                Console.WriteLine("DEBUG: " + message);
                for (int i = 0; i < array.GetLength(0); i++)
                {
                    for (int j = 0; j < array.GetLength(1); j++)
                    {
                        Console.Write(array[i, j].ToString("X2") + "\t");
                    }
                    Console.WriteLine();
                }
                Console.WriteLine();
            }
        }

        public static void printSchedule(byte[,] schedule, String message, bool forcePrint = false)
        {
            if (Program.debug || forcePrint)
            {
                Console.WriteLine("SCHEDULE DEBUG: " + message);
                for (int j = 0; j < schedule.GetLength(1); j++)
                {
                    Console.Write("Word #" + j + ": ");
                    for (int i = 0; i < schedule.GetLength(0); i++)
                    {
                        Console.Write(schedule[i, j].ToString("X2") + "\t");
                    }
                    Console.WriteLine();
                }
                Console.WriteLine();
            }
        }

        public static void printSingleWord(byte[] array, String message)
        {
            Console.WriteLine("DEBUG: " + message);
            for (int i = 0; i < array.GetLength(0); i++)
            {
                Console.WriteLine(array[i].ToString("X2") + "\t");
            }
            Console.WriteLine();
        }
    }
}
