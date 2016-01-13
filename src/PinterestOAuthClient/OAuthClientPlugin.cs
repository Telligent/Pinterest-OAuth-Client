using System;
using System.IO;
using System.Net;
using System.Web;
using System.Web.Script.Serialization;
using Telligent.DynamicConfiguration.Components;
using Telligent.Evolution.Extensibility.Authentication.Version1;
using Telligent.Evolution.Extensibility.Version1;
using OAuthData = Telligent.Evolution.Extensibility.Authentication.Version1.OAuthData;

namespace Telligent.Evolution.OAuth
{
    public class PinterestOAuthClient : IOAuthClient, IRequiredConfigurationPlugin
    {

        #region IPlugin

        public string Name { get { return "Pinterest"; } }
        public string Description { get { return "Provides user authentication through Pinterest."; } }
        public void Initialize() { }

        #endregion

        #region IConfigurablePlugin

        protected IPluginConfiguration Configuration
        {
            get;
            private set;
        }

        public void Update(IPluginConfiguration configuration)
        {
            Configuration = configuration;
        }

        // The configuration options are defined here. The values provided here
        //  are for convenience and not necessarily the values your OAuth client will
        //  require to be configured.  These may be changed as needed.
        public PropertyGroup[] ConfigurationOptions
        {
            get
            {
                var groups = new[] { new PropertyGroup("options", "Options", 0) };

                var consumerKey = new Property("ConsumerKey", "Consumer Key", PropertyType.String, 0, "");
                consumerKey.Rules.Add(new PropertyRule(typeof(Telligent.Evolution.Controls.PropertyRules.TrimStringRule), false));
                groups[0].Properties.Add(consumerKey);

                var consumerSecret = new Property("ConsumerSecret", "Consumer Secret", PropertyType.String, 0, "");
                consumerSecret.Rules.Add(new PropertyRule(typeof(Telligent.Evolution.Controls.PropertyRules.TrimStringRule), false));
                groups[0].Properties.Add(consumerSecret);

                return groups;
            }
        }

        #endregion

        #region IRequiredConfigurationPlugin Members

        public bool IsConfigured
        {
            get { return !string.IsNullOrEmpty(ConsumerKey) && !string.IsNullOrEmpty(ConsumerSecret); }
        }

        #endregion

        #region IOAuthClient Properties
        public string ClientName { get { return "Pinterest"; } }
        public string ClientType { get { return "pinterest"; } }
        public virtual string AuthorizeBaseUrl { get { return "https://api.pinterest.com/oauth"; } }
        public virtual string AccessTokenUrl { get { return "https://api.pinterest.com/v1/oauth/token"; } }
        public virtual string ConsumerKey { get { return Configuration.GetString("ConsumerKey"); } }
        public virtual string ConsumerSecret { get { return Configuration.GetString("ConsumerSecret"); } }
        public string ThemeColor { get { return "BD081C"; } }

        // Your privacy statement should include what privacy information
        //  is being collected about the user using this OAuth client.
        public string Privacy
        {
            get { return "Privacy statement"; }
        }

        // This is html that will be executed when a client logs out
        //  after being logged in through this OAuth client.
        //  Use this to perform further actions if needed.
        public string ClientLogoutScript
        {
            get { return ""; }
        }

        // Does nothing, potentially will be removed in a future release
        public bool Enabled { get { return true; } }

        private string _callbackUrl;
        public virtual string CallbackUrl
        {
            get
            {
                return _callbackUrl;
            }
            set
            {
                if (!string.IsNullOrEmpty(value) && value.StartsWith("http:"))
                    _callbackUrl = "https" + value.Substring(4);
                else
                    _callbackUrl = value;
            }
        }

        // This returns the url to an image representing your OAuth provider.
        // The image is shown when selecting what client to use when logging in and
        //  next to the user's avatar when logged in.
        public virtual string FileStoreKey { get { return "oauthimages"; } }
        public string IconUrl { get { return "https://developers.pinterest.com/static/img/badge.svg"; } }
        #endregion

        // Returns the Url to the OAuth service that will
        //  authorize the user and return back to Telligent Evolution.
        public string GetAuthorizationLink()
        {
            return string.Format("{0}/?client_id={1}&redirect_uri={2}&response_type=code&scope=read_public", 
                AuthorizeBaseUrl, 
                ConsumerKey, 
                HttpUtility.UrlEncode(CallbackUrl));
        }

        // This method is called when the user is redirected to
        //  Telligent Evolution after logging in through the OAuth service.
        // The method must return an OAuthData object based on the user's
        //  information provided by the service or return null.
        public OAuthData ProcessLogin(HttpContextBase context)
        {
            if (!Enabled || context.Request.QueryString["error"] != null)
                FailedLogin();

            if (context.Request.QueryString["code"] == null)
                FailedLogin();
            string authorizationCode = context.Request.QueryString["code"];

            _callbackUrl = RemoveVerificationCodeFromUri(context);

            string token = GetAccessToken(authorizationCode);

            if (string.IsNullOrEmpty(token))
                FailedLogin();

            return GetUserData(token);
        }

        #region Helpers

        private void FailedLogin()
        {
            throw new ApplicationException("OAuth Login Failed");
        }

		public string RemoveVerificationCodeFromUri(HttpContextBase context)
        {
            string uri = context.Request.Url.AbsoluteUri;
			int startIndex = uri.LastIndexOf("code=");
			if (startIndex < 0)
				return uri;

			int codeLength = uri.Substring(startIndex).IndexOf("&");
			if (codeLength < 0)
				codeLength = uri.Length - startIndex;

			if (uri.Length == startIndex + codeLength)
			{
				startIndex--;
			}
			codeLength++;


			// Remove the verification code param
			return uri.Remove(startIndex, codeLength);
		}

        /// <summary>
        /// Gets the access token for the security parameters.  Context will only have AccessToken and Expires values set.
        /// </summary>
        /// <param name="securityParams">MUST have "authCode" in the collection.</param>
        private string GetAccessToken(string authorizationCode)
        {
            // Use the authorization code to request an access token.
            string postData = string.Format("grant_type=authorization_code&client_id={0}&client_secret={1}&code={2}",
                                        ConsumerKey, ConsumerSecret, authorizationCode);

            var webClient = new WebClient();
            string responseData;
            try
            {
                webClient.Headers[HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded";
                responseData = webClient.UploadString(AccessTokenUrl, postData);
            }
            catch (Exception ex)
            {
                throw new ApplicationException("OAuth Web Request Failed", ex);
            }

            if (responseData.Length > 0)
            {
                //Store the returned access_token
                dynamic accessResponse = new JavaScriptSerializer().DeserializeObject(responseData);

                if (accessResponse["access_token"] != null)
                    return accessResponse["access_token"];
            }
            return null;
        }

        private OAuthData GetUserData(string token)
        {
            // Use Pinterest API to get details about the user
            string pinterestUrl = string.Format("https://api.pinterest.com/v1/me?access_token={0}", token);

            var webClient = new WebClient();
            string responseData;
            try
            {
                responseData = webClient.DownloadString(pinterestUrl);
            }
            catch (Exception ex)
            {
                throw new ApplicationException("OAuth Web Request Failed", ex);
            }

            if (responseData.Length > 0)
            {
                //Store the returned access_token
                PinterestUserDetails userDetails = new JavaScriptSerializer().Deserialize<PinterestUserDetails>(responseData);

                var data = new OAuthData
                    {
                        ClientId = userDetails.data.id, 
                        ClientType = ClientType, 
                        UserName = string.Format("{0}{1}", userDetails.data.first_name, userDetails.data.last_name), 
                        CommonName = string.Format("{0} {1}", userDetails.data.first_name, userDetails.data.last_name)
                    };

                return data;
            }
            return null;
        }

        private class PinterestUserDetails
        {
            public PinterestData data;
        }

        private class PinterestData
        {
            public string url { get; set; }
            public string first_name { get; set; }
            public string last_name { get; set; }
            public string id { get; set; }
        }
        #endregion
    }
}