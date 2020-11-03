using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CrossPlatformDSA.DSA.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace CrossPlatformDSA.Controllers
{
    public class KalkanController : Controller
    {
        private readonly ILibrary _lib;
        public KalkanController(ILibrary library)
        {
            _lib = library;
        }
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public IActionResult VerifyCMS([Required]IFormFile file)
        {
            byte [] arr;
            Stream stream= file.OpenReadStream();
            using (BinaryReader sr = new BinaryReader(stream))
            {
                arr=  sr.ReadBytes(Convert.ToInt32(stream.Length));
            }
            try
            {
                if (_lib.VerifyData(arr))
                {
                    ViewBag.Message = "Проверка прошла успешно";
                }
                else
                {
                    ViewBag.Message = "Проверка не прошла успешно";
                }
            }
            catch (Exception ex)
            {
                ViewBag.Message += ex.Message;
            }
            ViewBag.Platform = Environment.OSVersion.Platform.ToString();
            return View();
        }
    }
}