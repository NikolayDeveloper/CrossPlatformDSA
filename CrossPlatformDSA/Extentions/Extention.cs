using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CrossPlatformDSA
{
    public static class Extention
    {
        public static string ConvertToHexError(this ulong digit)
        {
            string strHex = "0x0" + digit.ToString("X");
            return strHex;
        }
        public static byte[] GetBytes(this string str)
        {
            byte[] arr = new byte[str.Length];
            for (int i = 0; i < arr.Length; i++)
            {
                arr[i] = Convert.ToByte(str[i]);
            }
            return arr;
        }
        public static string GetString(this byte[] arr)
        {
            StringBuilder stringBuilder = new StringBuilder(200);
            string result = "";
            for (int i = 0; i < arr.Length; i++)
            {
                char symbol = Convert.ToChar(arr[i]);
                if (symbol != '\0')
                {
                    stringBuilder.Append(symbol);
                }
                else
                {
                    break;
                }

            }
            result = stringBuilder.ToString();
            return result;
        }
    }
}
