
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web.Hosting;


/// Extra Comment
/// <summary>
/// Using this class you can inquiry the user's detail from AD, Check a user current status from AD and also Change the password of users.
/// </summary>
public static class ActiveDirectoryHelper
{

    /// <summary>
    /// Get a user detail from Active Directory
    /// </summary>
    /// <param name="username"></param>
    /// <returns></returns>
    public static UserDetails GetUserDetailsFor(string username)
    {
        if (string.IsNullOrEmpty(username))
            return null;

        var details = new UserDetails();

        try
        {
            using (HostingEnvironment.Impersonate())
            {
                // set up domain context
                using (var ctx = new PrincipalContext(ContextType.Domain))
                {

                    // find the user
                    var user = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, username);

                    if (user != null)
                    {
                        // get the underlying DirectoryEntry object from the UserPrincipal
                        details.IsUserExist = true;
                        var de = (DirectoryEntry)user.GetUnderlyingObject();

                        // now get the UserEntry object from the directory entry
                        var ue = (ActiveDs.IADsUser)de.NativeObject;

                        details.IsAccountLocked = ue.IsAccountLocked;
                        details.IsAccountActive = !ue.AccountDisabled;
                        details.PasswordExpirationDate = ue.PasswordExpirationDate;
                        details.HasPasswordExpired = ue.PasswordExpirationDate <= DateTime.Now;
                        details.PasswordNeverExpired = user.PasswordNeverExpires;

                        if (user.PasswordNeverExpires)
                        {
                            details.HasPasswordExpired = false;
                        }

                        if (user.LastPasswordSet.HasValue == false && user.PasswordNeverExpires == false)
                        {
                            details.ForceChangePassword = true;
                        }
                        else
                        {
                            details.ForceChangePassword = false;
                        }

                    }
                    else
                    {
                        details.IsUserExist = false;
                        details.IsAccountActive = false;
                        details.HasPasswordExpired = true;
                    }
                }
            }
        }
        catch (Exception e)
        {
            // in case something happened when fetching AD properties
            // you can do something here
            details.IsAccountActive = false;
        }

        return details;
    }

    /// <summary>
    /// Check current status of a user inside Active Directory
    /// </summary>
    /// <param name="username">UserName</param>
    /// <param name="password">Password</param>
    /// <returns>Converted AD string and code to UserStatus Enum</returns>
    public static UserStatus GetUserStatus(string username, string password)
    {
        if (string.IsNullOrEmpty(username))
            return UserStatus.UserNotFound;
        try
        {
            using (HostingEnvironment.Impersonate())
            {
                // set up domain context
                using (var ctx = new PrincipalContext(ContextType.Domain))
                {
                    var user = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, username);
                    if (user != null)
                    {
                        try
                        {
                            LdapConnection connection = new LdapConnection(ctx.ConnectedServer);
                            NetworkCredential credential = new NetworkCredential(username, password);
                            connection.Credential = credential;
                            connection.Bind();
                            return UserStatus.Authenticated;
                        }
                        catch (LdapException lexc)
                        {
                            String error = lexc.ServerErrorMessage;
                            return changeStringToStatus(error);
                        }
                        catch (Exception exc)
                        {
                            return changeStringToStatus(exc.Message);
                        }
                    }
                    else
                    {
                        return UserStatus.UserNotFound;
                    }
                }
            }
        }
        catch (Exception e)
        {
            // in case something happened when fetching AD properties                
            return UserStatus.UserNotFound;
        }
    }

    /// <summary>
    /// Change password for a user inside Active Directory
    /// </summary>
    /// <param name="username">User Name</param>
    /// <param name="currentPass">Current Password</param>
    /// <param name="newPass">New Password</param>    
    /// <returns></returns>
    public static ADMessage ChangePassword(string username, string currentPass, string newPass)
    {

        ADMessage messageResult = new ADMessage();

        #region Change Password
        try
        {
            using (HostingEnvironment.Impersonate())
            {
                // Get the domain context
                using (var ctx = new PrincipalContext(ContextType.Domain))
                {
                    if (!string.IsNullOrEmpty(username))
                    {
                        var user = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, username);
                        if (user != null)
                        {
                            user.ChangePassword(currentPass, newPass);
                            user.Save();
                            messageResult.Result = MessageStatus.Success;
                            messageResult.Messages.Add("The password has been successfully changed");

                        }
                        else
                        {
                            messageResult.Result = MessageStatus.Error;
                            messageResult.Messages.Add(string.Format("{0} not found", username));
                        }
                    }
                }
            }
        }
        catch (PasswordException ex)
        {
            messageResult.Result = MessageStatus.Error;
            if (ex.Message.Contains("0x800708C5")) // if there are other message Ids that you want to handle, add them here.
            {
                messageResult.Messages.Add("Please check minimum password age, password history or other details on password policy with you network administrator.");
            }
            else
            {
                messageResult.Messages.Add(ex.Message);
            }
        }
        #endregion
        return messageResult;
    }
    private static UserStatus changeStringToStatus(string errorMessage)
    {
        if (errorMessage.Contains("data 525,"))
        {
            return UserStatus.UserNotFound;
        }
        else if (errorMessage.Contains("data 52e,"))
        {
            return UserStatus.InvalidCredentials;
        }
        else if (errorMessage.Contains("data 530,"))
        {
            return UserStatus.NotPermittedToLogonAtThisTime;
        }
        else if (errorMessage.Contains("data 531,"))
        {
            return UserStatus.NotPermittedToLogonAtThisWorkstation;
        }
        else if (errorMessage.Contains("data 532,"))
        {
            return UserStatus.PasswordExpired;
        }
        else if (errorMessage.Contains("data 533,"))
        {
            return UserStatus.AccountDisabled;
        }
        else if (errorMessage.Contains("data 701,"))
        {
            return UserStatus.AccountExpired;
        }
        else if (errorMessage.Contains("data 773,"))
        {
            return UserStatus.UserMustResetPassword;
        }
        else if (errorMessage.Contains("data 775,"))
        {
            return UserStatus.UserAccountLocked;
        }
        else
        {
            return UserStatus.UserNotFound;
        }
    }
}

public enum UserStatus
{
    UserNotFound,//525​	
    InvalidCredentials,//52e
    NotPermittedToLogonAtThisTime, //530
    NotPermittedToLogonAtThisWorkstation, //531
    PasswordExpired, //532
    AccountDisabled,//533
    AccountExpired, //701
    UserMustResetPassword,//773
    UserAccountLocked, //775
    Authenticated

}
public enum MessageStatus
{
    Success = 1,
    Error = 2
}
public class ADMessage
{
    public ADMessage()
    {
        this.Messages = new List<string>();
    }
    public MessageStatus Result { get; set; }
    public List<string> Messages { get; set; }

}
public class UserDetails
{
    public bool PasswordNeverExpired { get; set; }
    public bool IsAccountLocked { get; set; }
    public bool IsAccountActive { get; set; }
    public bool HasPasswordExpired { get; set; }
    public DateTime PasswordExpirationDate { get; set; }
    public DateTime PasswordLastChanged { get; set; }
    public bool ForceChangePassword { get; set; }
    public bool IsUserExist { get; set; }
    public bool IsAuthenticate { get; set; }
}


