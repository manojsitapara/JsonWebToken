using System;
using System.Collections.Generic;
using System.Data.Entity.Migrations;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Web;
using Web_API_JWT.EntityFramework;

namespace Web_API_JWT.Domain
{
    public class hPayDomain
    {
        public User AuthenticateUser(string userName, string password)
        {
            using (var hPayEntities = new hPay_Demo_HSAEntities())
            {
                var hPayUser = hPayEntities.Users.FirstOrDefault(u => u.UserLogin == userName && u.Pswd == password);
                return hPayUser;
            }
        }

        public User GetUser(string userName)
        {

            using (var hPayEntities = new hPay_Demo_HSAEntities())
            {

                var hPayUser = hPayEntities.Users.FirstOrDefault(u => u.UserLogin == userName);
                hPayEntities.Entry<User>(hPayUser).Reload();
                return hPayUser;
            }
        }

        public bool ChangePassword(string userName, string oldPassword, string newPassword)
        {

            using (var hPayEntities = new hPay_Demo_HSAEntities())
            {
                var hPayUser = hPayEntities.Users.FirstOrDefault(u => u.UserLogin == userName && u.Pswd == oldPassword);
                var status = false;
                if (hPayUser != null)
                {
                    hPayUser.Pswd = newPassword;
                    hPayEntities.Users.AddOrUpdate(hPayUser);
                    hPayEntities.SaveChanges();
                    status = true;
                }
                return status;
            }


        }



        public bool ForgetPassword(string userName)
        {
            string password = string.Empty;
            bool status = false;
            using (var hPayEntities = new hPay_Demo_HSAEntities())
            {
                var hPayUser = hPayEntities.Users.FirstOrDefault(u => u.UserLogin == userName);
                if (hPayUser != null)
                {
                    password = hPayUser.Pswd;
                    SendPasswordViaEmail(password);
                    status = true;
                }
                return status;
            }

        }


 



       

        private void SendPasswordViaEmail(string password)
        {

            var fromAddress = new MailAddress("xoproject2014@gmail.com", "hPay");
            var toAddress = new MailAddress("manojs@cxcnetwork.com", "Manoj Sitapara");
            const string fromPassword = "Xocxc@123";
            const string subject = "hPay: Forget Password";
            string body = "Your password is: " + password;

            var smtp = new SmtpClient
            {
                Host = "smtp.gmail.com",
                Port = 587,
                EnableSsl = true,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(fromAddress.Address, fromPassword)
            };
            using (var message = new MailMessage(fromAddress, toAddress)
            {
                Subject = subject,
                Body = body
            })
            {
                smtp.Send(message);
            }
        }
    }
}