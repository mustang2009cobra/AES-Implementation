using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AESCSharp
{
    class KeySchedule
    {
        byte[,] schedule;
        int keyLength;
        int numRounds;

        byte[] Rcon = {
        0x00, 0x01, 0x02, 0x04, 0x08,
        0x10, 0x20, 0x40, 0x80, 0x1B,
        0x36 };

        public KeySchedule(byte[,] key){
            if(key.GetLength(1) == 4){
                schedule = new byte[4,44]; //For 128-bit key
                keyLength = 4;
                numRounds = 10;
            }
            else if(key.GetLength(1) == 6){
                schedule = new byte[4,52]; //For 192-bit key
                keyLength = 6;
                numRounds = 12;
            }
            else if(key.GetLength(1) == 8){
                schedule = new byte[4,60]; //For 256-bit key
                keyLength = 8;
                numRounds = 14;
            }
            else{
                Console.WriteLine("ERROR: KEY MATRIX PASSED TO SCHEDULE IS INCORRECT!!!!");
                schedule = null;
                return;
            }
            this.generateSchedule(key);
        }

        /**
         * Given the 128, 192, or 256-bit key, generates the key schedule for the
         *  encryption and decription algorithms
         * 
         * @return 
         */
        private void generateSchedule(byte[,] key)
        {
            //Schedule algorithm goes here
            byte[,] temp = new byte[4,1];

            int j = 0;

            //Put the initial key in the first few spots in the schedule
            while (j < this.keyLength)
            {
                for (int i = 0; i < key.GetLength(0); i++)
                {
                    schedule[i, j] = key[i, j];
                }
                j++;
            }

            //Generate the rest of the spots
            j = keyLength;

            while (j < (4 * (numRounds + 1)))
            {
                //Temp = w[i-1]
                for (int i = 0; i < temp.GetLength(0); i++)
                {
                    temp[i, 0] = schedule[i, j-1];
                }

                if (j % keyLength == 0)
                {
                    temp = SubWord(RotWord(temp));
                    temp[0, 0] = (byte) (temp[0, 0] ^ Rcon[j / keyLength]); //XOR with RCON (we only need to do the first byte)
                }
                else if (keyLength > 6 && (j % keyLength == 4))
                {
                    temp = SubWord(temp);
                }

                //w[1] = w[i-Nk] xor temp
                for (int i = 0; i < temp.GetLength(0); i++)
                {
                    schedule[i, j] = (byte) (schedule[i, j - keyLength] ^ temp[i, 0]); 
                }

                j = j + 1;
            }
        }

        /**
         * Substitutes a given word according to the sbox
         */ 
        private byte[,] SubWord(byte[,] word)
        {
            byte[,] subbedWord = new byte[4,1];
            for (int i = 0; i < word.GetLength(0); i++)
            {
                subbedWord[i,0] = subByte(word[i,0]);
            }

            return subbedWord;
        }

        /**
         * Substitutes a single byte according to the S-box defined in the AES spec
         * @param val
         * @return 
         */
        private byte subByte(byte val)
        {
            byte[,] sBox = Cipher.getSBox();
            String valStr = val.ToString("X2");
            String firstNumStr = valStr.Substring(0, 1);
            String secondNumStr = valStr.Substring(1, 1);

            int firstNum = int.Parse(firstNumStr, System.Globalization.NumberStyles.HexNumber);
            int secondNum = int.Parse(secondNumStr, System.Globalization.NumberStyles.HexNumber);

            return sBox[firstNum, secondNum];
        }

        /**
         * Rotates the given word
         */
        private byte[,] RotWord(byte[,] word)
        {
            byte[,] rotatedWord = new byte[4, 1];

            byte temp = word[0,0];
            for (int i = 0; i < (word.GetLength(0) - 1); i++)
            {
                rotatedWord[i, 0] = word[i + 1, 0];
            }
            rotatedWord[3, 0] = temp;
            return rotatedWord;
        }

        /**
         * Returns the schedule
         */ 
        public byte[,] getSchedule()
        {
            return schedule;
        }
    }
}
