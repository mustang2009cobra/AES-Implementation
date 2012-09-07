using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AESCSharp
{
    class InverseCipher
    {
        byte[,] input;
        byte[,] schedule;
        byte[,] state;
        int keyLength;

        static byte[,] invSBox =  { //Substitution box for inverse cipher
        { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb } ,
        { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb } ,
        { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e } ,
        { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 } ,
        { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 } ,
        { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 } ,
        { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 } ,
        { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b } ,
        { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 } ,
        { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e } ,
        { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b } ,
        { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 } ,
        { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f } ,
        { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef } ,
        { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 } ,
        { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }
        };
    
        public InverseCipher(byte[,] input, byte[,] schedule, int keyLength){
            this.input = input;
            this.schedule = schedule;
            this.keyLength = keyLength;
        }

        public static byte[,] getInvSBox()
        {
            return invSBox;
        }
    
        public byte[,] decrypt(){
            this.state = Program.copyDoubleArray(this.input);

            if (keyLength == 128)
            {
                //First round
                addRoundKey(10); //somehow get the 4x4 round key from schedule

                //NINE SAME ROUNDS
                for (int i = 9; i > 0; i--)
                {
                    Program.Debug("Round #" + (i + 1));
                    invShiftRows();
                    invSubBytes();
                    addRoundKey(i);
                    invMixColumns();
                    Program.printArray(state, "After round #" + (i + 1));
                }

                //LAST ROUND
                Program.Debug("Final round");
                invShiftRows();
                invSubBytes();
                addRoundKey(0);
            }
            else if (keyLength == 192)
            {
                //First round
                addRoundKey(12); //somehow get the 4x4 round key from schedule

                //ELEVEN SAME ROUNDS
                for (int i = 11; i > 0; i--)
                {
                    Program.Debug("Round #" + (i + 1));
                    invShiftRows();
                    invSubBytes();
                    addRoundKey(i);
                    invMixColumns();
                    Program.printArray(state, "After round #" + (i + 1));
                }

                //LAST ROUND
                Program.Debug("Final round");
                invShiftRows();
                invSubBytes();
                addRoundKey(0);
            }
            else if (keyLength == 256)
            {
                //First round
                addRoundKey(14); //somehow get the 4x4 round key from schedule

                //THIRTEEN SAME ROUNDS
                for (int i = 13; i > 0; i--)
                {
                    Program.Debug("Round #" + (i + 1));
                    invShiftRows();
                    invSubBytes();
                    addRoundKey(i);
                    invMixColumns();
                    Program.printArray(state, "After round #" + (i + 1));
                }

                //LAST ROUND
                Program.Debug("Final round");
                invShiftRows();
                invSubBytes();
                addRoundKey(0);
            }
            else
            {
                throw new Exception("Incorrect key length while decrypting file");
            }

            byte[,] output = Program.copyDoubleArray(state);

            return output;
        }

        /**
         * Given a 4x4 round key, XORs the state array with the round key
         * @param roundKey 
         */
        private void addRoundKey(int roundNumber)
        {
            Program.printArray(state, "Before AddRoundKey");

            for (int i = 0; i < state.GetLength(0); i++)
            {
                for (int j = 0; j < state.GetLength(1); j++)
                {
                    byte stateVar = state[i, j];
                    byte roundVar = schedule[i, ((roundNumber * 4) + j)];
                    state[i, j] = (byte)(stateVar ^ roundVar); //XOR round key with state ("ADD")
                }
            }

            Program.printArray(state, "After AddRoundKey");
        }

        /**
         * Right shifts the rows according to the AES algorithm
         */
        private void invShiftRows(){
            Program.printArray(state, "Before ShiftRows");

            //Shift the second row one over to the RIGHT
            var secondTemp1 = state[1, 3];
            state[1, 3] = state[1, 2];
            state[1, 2] = state[1, 1];
            state[1, 1] = state[1, 0];
            state[1, 0] = secondTemp1;

            //Shift the third row two over to the RIGHT
            var thirdTemp1 = state[2, 2];
            var thirdTemp2 = state[2, 3];
            state[2, 3] = state[2, 1];
            state[2, 2] = state[2, 0];
            state[2, 1] = thirdTemp2;
            state[2, 0] = thirdTemp1;

            //Shift the fourth row three over
            var fourthTemp1 = state[3, 0];
            var fourthTemp2 = state[3, 2];
            var fourthTemp3 = state[3, 3];
            state[3, 0] = state[3, 1];
            state[3, 1] = fourthTemp2;
            state[3, 2] = fourthTemp3;
            state[3, 3] = fourthTemp1;

            Program.printArray(state, "After ShiftRows");
        }

        /**
         * Substitutes the bytes according to the Inverse S-box defined in the specs
         */
        private void invSubBytes(){
            Program.printArray(state, "Before SubBytes"); //DEBUG

            for (int i = 0; i < state.GetLength(0); i++)
            {
                for (int j = 0; j < state.GetLength(1); j++)
                {
                    state[i, j] = subByte(state[i, j]);
                }
            }

            Program.printArray(state, "After SubBytes"); //DEBUG
        }
    

        private void invMixColumns(){
            //For each column in the state array
            for (int j = 0; j < state.GetLength(1); j++)
            {
                byte newEntry0 = (byte)((multiply(state[0, j], 14)) ^ (multiply(state[1, j], 11)) ^ (multiply(state[2, j], 13)) ^ (multiply(state[3, j], 9)));
                byte newEntry1 = (byte)((multiply(state[0, j], 9)) ^ (multiply(state[1, j], 14)) ^ (multiply(state[2, j],11)) ^ (multiply(state[3, j], 13)));
                byte newEntry2 = (byte)((multiply(state[0, j], 13)) ^ (multiply(state[1, j], 9)) ^ (multiply(state[2, j], 14)) ^ (multiply(state[3, j], 11)));
                byte newEntry3 = (byte)((multiply(state[0, j], 11)) ^ (multiply(state[1, j], 13)) ^ (multiply(state[2, j], 9)) ^ (multiply(state[3, j], 14)));

                state[0, j] = newEntry0;
                state[1, j] = newEntry1;
                state[2, j] = newEntry2;
                state[3, j] = newEntry3;
            }
        }

        private byte multiply(byte entry, int coefficient)
        {
            var mult1 = entry;
            var mult2 = xtime(mult1);
            var mult4 = xtime(mult2);
            var mult8 = xtime(mult4);

            if (coefficient == 9)
            {
                return (byte)(mult8 ^ mult1);
            }
            else if (coefficient == 11)
            {
                return (byte)(mult8 ^ mult2 ^ mult1);
            }
            else if (coefficient == 13)
            {
                return (byte)(mult8 ^ mult4 ^ mult1);
            }
            else if (coefficient == 14)
            {
                return (byte)(mult8 ^ mult4 ^ mult2);
            }
            else
            {
                throw new Exception("Coefficient passed to decrypt multiply function is invalid");
            }
        }

        /**
         * Multiplies a byte by the polynomial x
         */ 
        private byte xtime(byte entry)
        {
            byte newByte = (byte)(entry << 1); //Left shift (don't care about overflow beyond 8-bits)

            //Check to see if the highest bit is set (thanks to http://stackoverflow.com/questions/4854207/get-a-specific-bit-from-byte for the black magic for this)
            if ((byte)(entry & (1 << 7)) != 0)
            {
                byte xorVar = 27;
                newByte = (byte)(newByte ^ xorVar);
            }

            return newByte;
        }

        /**
         * Substitutes a single byte according to the Inverse S-box defined in the AES spec
         * @param val
         * @return 
         */
        private byte subByte(byte val)
        {
            String valStr = val.ToString("X2");
            String firstNumStr = valStr.Substring(0, 1);
            String secondNumStr = valStr.Substring(1, 1);

            int firstNum = int.Parse(firstNumStr, System.Globalization.NumberStyles.HexNumber);
            int secondNum = int.Parse(secondNumStr, System.Globalization.NumberStyles.HexNumber);

            return InverseCipher.invSBox[firstNum, secondNum];
        }
    }
}
