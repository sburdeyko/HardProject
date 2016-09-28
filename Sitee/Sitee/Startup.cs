using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Sitee.Startup))]
namespace Sitee
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
