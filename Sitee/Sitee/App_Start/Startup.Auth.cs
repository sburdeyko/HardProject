using System;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.Twitter;
using Owin;
using Sitee.Models;

namespace Sitee
{
    public partial class Startup
    {
        // Дополнительные сведения о настройке проверки подлинности см. по адресу: http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Настройка контекста базы данных, диспетчера пользователей и диспетчера входа для использования одного экземпляра на запрос
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            // Включение использования файла cookie, в котором приложение может хранить информацию для пользователя, выполнившего вход,
            // и использование файла cookie для временного хранения информации о входах пользователя с помощью стороннего поставщика входа
            // Настройка файла cookie для входа
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Позволяет приложению проверять метку безопасности при входе пользователя.
                    // Эта функция безопасности используется, когда вы меняете пароль или добавляете внешнее имя входа в свою учетную запись.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });            
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Позволяет приложению временно хранить информацию о пользователе, пока проверяется второй фактор двухфакторной проверки подлинности.
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // Позволяет приложению запомнить второй фактор проверки имени входа. Например, это может быть телефон или почта.
            // Если выбрать этот параметр, то на устройстве, с помощью которого вы входите, будет сохранен второй шаг проверки при входе.
            // Точно так же действует параметр RememberMe при входе.
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            ////app.UseTwitterAuthentication(
            ////   consumerKey: "DhditAJTujoUEUAvPg0I1ZXbx",
            ////   consumerSecret: "OTn0A4cqvniF66BfPIjGqPpGiljFWnDJzYhtbMPCJnrY3kzwd1");

            app.UseFacebookAuthentication(
                appId: "1347706098592644",
                appSecret: "41b60dae3eb62042cef85f241e89760f");

            app.UseVkontakteAuthentication(
                appId: "5628661", appSecret: "yKXnsApq3rIGpLGRGvF9", scope: "offline, nohttps");

            app.UseTwitterAuthentication(new TwitterAuthenticationOptions
            {
                ConsumerKey = "DhditAJTujoUEUAvPg0I1ZXbx",
                ConsumerSecret = "OTn0A4cqvniF66BfPIjGqPpGiljFWnDJzYhtbMPCJnrY3kzwd1",
                BackchannelCertificateValidator =
                  new Microsoft.Owin.Security.CertificateSubjectKeyIdentifierValidator(
                    new[] {
        // VeriSign Class 3 Secure Server CA - G2
        "A5EF0B11CEC04103A34A659048B21CE0572D7D47",
        // VeriSign Class 3 Secure Server CA - G3
        "0D445C165344C1827E1D20AB25F40163D8BE79A5", 
        // VeriSign Class 3 Public Primary Certification Authority - G5
        "7FD365A7C2DDECBBF03009F34339FA02AF333133", 
        // Symantec Class 3 Secure Server CA - G4
        "39A55D933676616E73A761DFA16A7E59CDE66FAD", 
        // Symantec Class 3 EV SSL CA - G3
        "‎add53f6680fe66e383cbac3e60922e3b4c412bed", 
        // VeriSign Class 3 Primary CA - G5
        "4eb6d578499b1ccf5f581ead56be3d9b6744a5e5", 
        // DigiCert SHA2 High Assurance Server C‎A 
        "5168FF90AF0207753CCCD9656462A212B859723B",
        // DigiCert High Assurance EV Root CA 
        "B13EC36903F8BF4701D498261A0802EF63642BC3"
      })
            });
        }
    }
}