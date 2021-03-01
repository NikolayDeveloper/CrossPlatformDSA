using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CrossPlatformDSA
{
    public static class Extention
    {
        /// <summary>
        ///  возвращает строку с пояснением на русском языке и bool результат проверки
        /// </summary>
        /// <param name="err">код ошибки</param>
        /// <param name="errStr">расшифровка ошибки</param>
        /// <param name="message">получение желаемой строки</param>
        /// <returns></returns>
        public static KeyValuePair<string,bool> SpecificCodeError(this uint err,string errStr,string message)
        {
            string CodeErrorHexToString = "0x0" + err.ToString("X");
            KeyValuePair<string, bool> keyValue;
            if (err == 0 && string.IsNullOrEmpty(errStr) && !string.IsNullOrEmpty(message))
            {
                keyValue = new KeyValuePair<string, bool>(message, true);
            }
            else if (err == 0 && !string.IsNullOrEmpty(errStr) && !string.IsNullOrEmpty(message))
            {
                keyValue = new KeyValuePair<string, bool>(message, true);
            }
            else if (err == 0 && string.IsNullOrEmpty(errStr) && string.IsNullOrEmpty(message))
            {
                keyValue = new KeyValuePair<string, bool>("Добавьте собщение в параметр message ", true);
            }
            else if (err == 0 && !string.IsNullOrEmpty(errStr) && string.IsNullOrEmpty(message))
            {
                keyValue = new KeyValuePair<string, bool>("Неизвестный удостоверяющий центр. Проверка цепочки сертификатов прошла неуспешно", false);
            }
            //Если при проверке подписи выходит ошибка -0x08F00042, то сертификат просрочен.
            else if (CodeErrorHexToString== "0x08F00042" && !string.IsNullOrEmpty(errStr))
            {
                keyValue = new KeyValuePair<string,bool>("Неизвестный удостоверяющий центр. Проверка цепочки сертификатов прошла неуспешно", false);
            }
            // числ 12- это код ошибки , что crl файл истек и нужно скачать новую версию
            else if (err == 12 && !string.IsNullOrEmpty(errStr))
            {
                keyValue = new KeyValuePair<string, bool>("crl файл истек, загрузите новую версию", false);
            }
            else
            {
                keyValue = new KeyValuePair<string, bool>(errStr, false);
            }
            
            return keyValue;
        }
        public static KeyValuePair<string, bool> SpecificCodeError(this ulong err, string errStr, string message)
        {
            string CodeErrorHexToString = "0x0" + err.ToString("X");
            KeyValuePair<string, bool> keyValue;
            if (err == 0 && string.IsNullOrEmpty(errStr) && !string.IsNullOrEmpty(message))
            {
                keyValue = new KeyValuePair<string, bool>(message, true);
            }
            else if (err == 0 && !string.IsNullOrEmpty(errStr) && !string.IsNullOrEmpty(message))
            {
                keyValue = new KeyValuePair<string, bool>(message, true);
            }
            else if (err == 0 && string.IsNullOrEmpty(errStr) && string.IsNullOrEmpty(message))
            {
                keyValue = new KeyValuePair<string, bool>("Добавьте собщение в параметр message ", true);
            }
            else if (err == 0 && !string.IsNullOrEmpty(errStr) && string.IsNullOrEmpty(message))
            {
                keyValue = new KeyValuePair<string, bool>("Неизвестный удостоверяющий центр. Проверка цепочки сертификатов прошла неуспешно", false);
            }
            //Если при проверке подписи выходит ошибка -0x08F00042, то сертификат просрочен.
            else if (CodeErrorHexToString == "0x08F00042" && !string.IsNullOrEmpty(errStr))
            {
                keyValue = new KeyValuePair<string, bool>("Неизвестный удостоверяющий центр. Проверка цепочки сертификатов прошла неуспешно", false);
            }
            // числ 12- это код ошибки , что crl файл истек и нужно скачать новую версию
            else if (err == 12 && !string.IsNullOrEmpty(errStr))
            {
                keyValue = new KeyValuePair<string, bool>("crl файл истек, загрузите новую версию", false);
            }
            else
            {
                keyValue = new KeyValuePair<string, bool>(errStr, false);
            }

            return keyValue;
        }
        /// <summary>
        /// перевод из цифрового значение ошибки в строку
        /// </summary>
        /// <param name="digit"></param>
        /// <returns></returns>
        public static string ConvertToHexError(this ulong digit)
        {
            string strHex = "0x0" + digit.ToString("X");
            return strHex;
        }
        /// <summary>
        /// перевод из цифрового значение ошибки в строку
        /// </summary>
        /// <param name="digit"></param>
        /// <returns></returns>
        public static string ConvertToHexErrorUint(this uint digit)
        {
            string strHex = "0x0" + digit.ToString("X");
            return strHex;
        }
        /// <summary>
        /// получить байты из строки
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static byte[] GetBytes(this string str)
        {
            byte[] arr = new byte[str.Length];
            for (int i = 0; i < arr.Length; i++)
            {
                arr[i] = Convert.ToByte(str[i]);
            }
            return arr;
        }
        /// <summary>
        /// получить строку из байт
        /// </summary>
        /// <param name="arr"></param>
        /// <returns></returns>
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

        public static string GetString2(this byte[] arr)
        {
            StringBuilder stringBuilder = new StringBuilder(200);
            string result = "";

            char[] charArray = Encoding.UTF8.GetChars(arr);

            for (int i = 0; i < arr.Length; i++)
            {
                if (charArray[i] != '\0')
                {
                    stringBuilder.Append(charArray[i]);
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
