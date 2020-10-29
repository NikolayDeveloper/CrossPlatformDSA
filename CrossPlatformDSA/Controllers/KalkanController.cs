using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CrossPlatformDSA.DSA.Interfaces;
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
        public IActionResult VerifyCMS()
        {
            return View();
        }
    }
}