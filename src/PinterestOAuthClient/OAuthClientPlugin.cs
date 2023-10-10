using System;
using System.Web;
using System.Threading;
using System.Threading.Tasks;
using Telligent.Evolution.Extensibility;
using Telligent.Evolution.Extensibility.Api.Version1;
using Telligent.Evolution.Extensibility.Version1;
using Telligent.Evolution.Extensibility.Authentication.Version2;
using Telligent.Evolution.Extensibility.Version2;
using Telligent.Evolution.Extensibility.Configuration.Version1;

namespace Telligent.Evolution.OAuth
{
	public class PinterestOAuthClient : IExternalLinkedAuthenticationProvider, IRequiredConfigurationPlugin, IConfigurablePlugin, IPlugin
	{
		private IHttp _http;
		private IPluginConfiguration _configuration;
		private IExternalLinkedAuthenticationProviderController _authController;
		private string _redirectUri;

		private const string CLIENT_ID = "ClientId";
		private const string CLIENT_SECRET = "ClientSecret";

		#region IPlugin

		public string Name { get { return "Pinterest"; } }
		public string Description { get { return "Provides user authentication through Pinterest."; } }
		public void Initialize() 
		{
			_http = Apis.Get<IHttp>();
		}

		#endregion

		#region IConfigurablePlugin

		public void Update(IPluginConfiguration configuration)
		{
			_configuration = configuration;
		}

		public PropertyGroup[] ConfigurationOptions
		{
			get
			{
				var groups = new[] { new PropertyGroup { Id = "options", LabelText = "Options", OrderNumber = 0 } };

				groups[0].Properties.Add(new Property
				{
					Id = "RedirectUri",
					LabelText = "Redirect URI",
					DescriptionText = "Use this URL when configuring this OAuth client with Pinterest.",
					DataType = "string",
					OrderNumber = 0,
					DefaultValue = _redirectUri,
					Visible = true,
					Editable = false
				});

				groups[0].Properties.Add(new Property
				{
					Id = CLIENT_ID,
					LabelText = "Client ID",
					DataType = "string",
					OrderNumber = 0,
					DefaultValue = "",
					Options = new System.Collections.Specialized.NameValueCollection { { "obscure", "true" } }
				});

				groups[0].Properties.Add(new Property
				{
					Id = CLIENT_SECRET,
					LabelText = "Client Secret",
					DataType = "string",
					OrderNumber = 1,
					DefaultValue = "",
					Options = new System.Collections.Specialized.NameValueCollection { { "obscure", "true" } }
				});

				return groups;
			}
		}

		#endregion

		#region IRequiredConfigurationPlugin Members

		public bool IsConfigured
		{
			get { return !string.IsNullOrEmpty(_configuration.GetString(CLIENT_ID)) && !string.IsNullOrEmpty(_configuration.GetString(CLIENT_SECRET)); }
		}

		#endregion

		#region IExternalLinkedAuthenticationProvider

		public string Id { get; } = "pinterest";
		public string NameHtml { get; } = "Pinterest";

		public Task<string> GetInitializeUrl(ExternalLinkedAuthenticationInitializeOptions options)
		{
			return TaskUtility.FromSync<string>(() =>
			{
				return $"https://api.pinterest.com/oauth/?client_id={HttpUtility.UrlEncode(_configuration.GetString(CLIENT_ID))}&redirect_uri={HttpUtility.UrlEncode(_redirectUri)}&response_type=code&scope=user_accounts:read&state={HttpUtility.UrlEncode(options.State)}";
			});
		}
		
		public void SetController(IExternalLinkedAuthenticationProviderController controller)
		{
			_authController = controller;
			_authController.CssColor = () => "#BD081C";
			_authController.IconUrl = () => "https://developers.pinterest.com/static/img/badge.svg";
			_authController.PrivacyDetailsHtml = () => "Privacy statement";
			_redirectUri = _authController.RegisterAndGetCallbackUrl(async (options) =>
			{
				if (options.QueryString["error"] != null)
					throw new Exception($"Login Failed: {options.QueryString["error"]}");

				if (options.QueryString["code"] == null)
					throw new Exception("Login Failed: No code was received.");

				string authorizationCode = options.QueryString["code"];
				string state = options.QueryString["state"];
				string token = await GetAccessToken(authorizationCode, options.Token);

				if (string.IsNullOrEmpty(token))
					throw new Exception("Login Failed: A token could not be retrieved.");

				_authController.SetLinkedUserData(await GetUserData(token, options.Token), state);
			});
		}

		#endregion

		#region Helpers

		private async Task<string> GetAccessToken(string authorizationCode, CancellationToken cancellationToken)
		{
			var httpOptions = new HttpOptions
			{
				BypassUrlFiltering = true,
				CancellationToken = cancellationToken
			};
			httpOptions.Headers["Content-Type"] = "application/x-www-form-urlencoded";
			httpOptions.Headers["Authorization"] = "Basic " + System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{_configuration.GetString(CLIENT_ID)}:{_configuration.GetString(CLIENT_SECRET)}"));

			var httpResponse = await _http.PostAsync(
				"https://api.pinterest.com/v5/oauth/token", 
				$"grant_type=authorization_code&code={HttpUtility.UrlEncode(authorizationCode)}&redirect_uri={HttpUtility.UrlEncode(_redirectUri)}", 
				httpOptions);

			if (httpResponse.Data != null && httpResponse.Data.access_token != null)
				return httpResponse.Data.access_token;

			return null;
		}

		private async Task<ExternalLinkedAuthenticationUserData> GetUserData(string token, CancellationToken cancellationToken)
		{
			var httpOptions = new HttpOptions
			{
				BypassUrlFiltering = true,
				CancellationToken = cancellationToken
			};
			httpOptions.Headers["Authorization"] = $"Bearer ${token}";

			var httpResponse = await _http.GetAsync(
				$"https://api.pinterest.com/v5/user_account",
				httpOptions);

			if (httpResponse.Data != null)
				return new ExternalLinkedAuthenticationUserData
				{
					AvatarUrl = httpResponse.Data.profile_image,
					ExternalUserId = httpResponse.Data.id,
					UserName = httpResponse.Data.username
				};

			return null;
		}

		#endregion
	}
}