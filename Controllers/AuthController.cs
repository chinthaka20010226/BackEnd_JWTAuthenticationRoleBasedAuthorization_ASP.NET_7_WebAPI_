using Microsoft.AspNetCore.Mvc;

namespace backend_dotnet7.Controllers
{
    public class AuthController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
