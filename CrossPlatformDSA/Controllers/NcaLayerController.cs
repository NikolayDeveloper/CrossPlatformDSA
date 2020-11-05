using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CrossPlatformDSA.DSA.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace CrossPlatformDSA.Controllers
{
    public class NcaLayerController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
        [HttpPost]
        public async Task<string> FileForCMS([Required]IFormFile file)
        {
            byte[] bytes = null;
            // считываем переданный файл в массив байтов
            using (var binaryReader = new BinaryReader(file.OpenReadStream()))
            {
                bytes = binaryReader.ReadBytes((int)file.Length);
            }
            string fileBase64 = Convert.ToBase64String(bytes);
            return fileBase64;
        }
    }
}