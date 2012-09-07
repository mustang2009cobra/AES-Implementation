using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AESCSharp
{
    class Cipher
    {
        byte[,] input;
        byte[,] schedule;
        byte[,] state;
        int keyLength;

        static byte[,] sBox = { //Substitution box for Cipher
        {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
        {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
        {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
        {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
        {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
        {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
        {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
        {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
        {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
        {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
        {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
        {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
        {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
        {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
        {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
        {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d,0x0f, 0xb0, 0x54, 0xbb, 0x16}
        };

        public Cipher(byte[,] input, byte[,] schedule, int keyLength){
            this.input = input;
            this.schedule = schedule;
            this.keyLength = keyLength;
        }

        public static byte[,] getSBox()
        {
            return sBox;
        }
    
        /**
         * Given a 4x4 array of plaintext and the cipher key, encrypts
         * @param in A double array of size 4x4 where each element is a single byte
         * @param key An array of size Nk where each entry is a 4-byte word
         * @return A double array of size 4x4 consisting of the encrypted ciphertext data
         */
        public byte[,] encrypt(){
            this.state = Program.copyDoubleArray(this.input);
        
            //FIRST ROUND
            addRoundKey(0); //somehow get the 4x4 round key from schedule

            Program.printArray(state, "After first initial round");

            if(keyLength == 128){
                //NINE SAME ROUNDS
                for(int i = 0; i < 9; i++){
                    Program.Debug("Round #" + (i+1));
                    subBytes();
                    shiftRows();
                    mixColumns();
                    addRoundKey(i+1); //Somehow get the correct 4x4 round key from the schedule
                    Program.printArray(state, "After round #" + (i+1));
                }

                //LAST ROUND
                Program.Debug("Final round");
                subBytes();
                shiftRows();
                addRoundKey(10);
            }else if(keyLength == 192){
                //ELEVEN SAME ROUNDS
                for(int i = 0; i < 11; i++){
                    Program.Debug("Round #" + (i+1));
                    subBytes();
                    shiftRows();
                    mixColumns();
                    addRoundKey(i+1); //Somehow get the correct 4x4 round key from the schedule
                    Program.printArray(state, "After round #" + (i + 1));
                }

                //LAST ROUND
                Program.Debug("Final round");
                subBytes();
                shiftRows();
                addRoundKey(12);
            }
            else if(keyLength == 256){
                //THIRTEEN SAME ROUNDS
                for(int i = 0; i < 13; i++){
                    Program.Debug("Round #" + (i+1));
                    subBytes();
                    shiftRows();
                    mixColumns();
                    addRoundKey(i+1); //Somehow get the correct 4x4 round key from the schedule
                    Program.printArray(state, "After round #" + (i + 1));
                }

                //LAST ROUND
                Program.Debug("Final round");
                subBytes();
                shiftRows();
                addRoundKey(14);
            }
            else{
                throw new Exception("Incorrect key length while encrypting file");
            }

            byte[,] output = Program.copyDoubleArray(state);
        
            return output;
        }
    
        /**
         * Given a 4x4 round key, XORs the state array with the round key
         * @param roundKey 
         */
        private void addRoundKey(int roundNumber){
            Program.printArray(state, "Before AddRoundKey");

            for (int i = 0; i < state.GetLength(0); i++)
            {
                for (int j = 0; j < state.GetLength(1); j++)
                {
                    byte stateVar = state[i, j];
                    byte roundVar = schedule[i, ((roundNumber * 4) + j)];
                    state[i,j] = (byte) (stateVar ^ roundVar); //XOR round key with state ("ADD")
                }
            }

            Program.printArray(state, "After AddRoundKey");
        }
    
        /**
         * Substitutes the bytes according to the S-box defined in the specs
         */
        private void subBytes(){
            Program.printArray(state, "Before SubBytes"); //DEBUG

            for (int i = 0; i < state.GetLength(0); i++)
            {
                for (int j = 0; j < state.GetLength(1); j++)
                {
                    state[i,j] = subByte(state[i,j]);
                }
            }

            Program.printArray(state, "After SubBytes"); //DEBUG
        }
    
        /**
         * Left shifts the rows according to the AES algorithm
         */
        private void shiftRows(){
            Program.printArray(state, "Before ShiftRows");
        
            //Shift the second row one over
            var secondTemp1 = state[1, 0];
            for (int j = 0; j < state.GetLength(1) - 1; j++)
            {
                state[1, j] = state[1, j + 1];
            }
            state[1, 3] = secondTemp1;
        
            //Shift the third row two over
            var thirdTemp1 = state[2, 0];
            var thirdTemp2 = state[2, 1];
            state[2, 0] = state[2,2];
            state[2, 1] = state[2,3];
            state[2, 2] = thirdTemp1;
            state[2, 3] = thirdTemp2;

            //Shift the fourth row three over
            var fourthTemp1 = state[3, 0];
            var fourthTemp2 = state[3, 1];
            var fourthTemp3 = state[3, 2];
            state[3, 0] = state[3, 3];
            state[3, 1] = fourthTemp1;
            state[3, 2] = fourthTemp2;
            state[3, 3] = fourthTemp3;

            Program.printArray(state, "After ShiftRows");
        }
    
        /**
         * Mixes the columns up according to the AES specs
         */
        private void mixColumns(){
            Program.printArray(state, "Before MixColumns");

            //For each column in the state array
            for (int j = 0; j < state.GetLength(1); j++)
            {
                byte newEntry0 = (byte) ((multiply(state[0,j], 2)) ^ (multiply(state[1,j], 3)) ^ (state[2,j]) ^ (state[3,j]));
                byte newEntry1 = (byte)((state[0, j]) ^ (multiply(state[1, j], 2)) ^ (multiply(state[2, j], 3)) ^ (state[3, j]));
                byte newEntry2 = (byte)((state[0, j]) ^ (state[1, j]) ^ (multiply(state[2, j], 2)) ^ (multiply(state[3, j], 3)));
                byte newEntry3 = (byte)((multiply(state[0, j], 3)) ^ (state[1, j]) ^ (state[2, j]) ^ (multiply(state[3, j], 2)));

                state[0, j] = newEntry0;
                state[1, j] = newEntry1;
                state[2, j] = newEntry2;
                state[3, j] = newEntry3;
            }

            Program.printArray(state, "After MixColumns");
        }

        /**
         * Multiplies an entry by the given coefficient
         * -For our AES purposes, we only multiply by 1, 2, or 3
         */
        private byte multiply(byte entry, int coefficient)
        {
            if(coefficient == 1)
            {
                return entry;
            }
            else if (coefficient == 2)
            {
                var newByte = xtime(entry);
                return newByte;
            }
            else if (coefficient == 3)
            {
                var newByte = xtime(entry);
                newByte = (byte)(newByte ^ entry); //Add the multiplied by 2 value with the entry value (that is equivalent to multiplying by 3)
                return newByte;
            }
            else
            {
                throw new Exception("Coefficient passed to encrypt multiply function is invalid");
            }
        }

        /**
         * Multiplies a byte by the polynomial x
         */ 
        private byte xtime(byte entry)
        {
            byte newByte = (byte) (entry << 1); //Left shift (don't care about overflow beyond 8-bits)

            //Check to see if the highest bit is set (thanks to http://stackoverflow.com/questions/4854207/get-a-specific-bit-from-byte for the black magic for this)
            if((byte) (entry & (1 << 7)) != 0){ 
                byte xorVar = 27;
                newByte = (byte)(newByte ^ xorVar);
            }

            return newByte;
        }

        /*****************************HELPER FUNCTIONS*****************************/
    
        /**
         * Substitutes a single byte according to the S-box defined in the AES spec
         * @param val
         * @return 
         */
        private byte subByte(byte val){
            String valStr = val.ToString("X2");
            String firstNumStr = valStr.Substring(0, 1);
            String secondNumStr = valStr.Substring(1, 1);

            int firstNum = int.Parse(firstNumStr, System.Globalization.NumberStyles.HexNumber);
            int secondNum = int.Parse(secondNumStr, System.Globalization.NumberStyles.HexNumber);

            return Cipher.sBox[firstNum, secondNum];
        }
    }
}
