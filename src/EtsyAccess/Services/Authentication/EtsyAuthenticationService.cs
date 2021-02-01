using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using CuttingEdge.Conditions;
using EtsyAccess.Exceptions;
using EtsyAccess.Shared;
using EtsyAccess.Models.Configuration;
using EtsyAccess.Models.Throttling;
using Polly;

namespace EtsyAccess.Services.Authentication
{
	public class OAuthCredentials
	{
		public string LoginUrl { get; private set; }
		public string Token { get; private set; }
		public string TokenSecret { get; private set; }

		public OAuthCredentials( string loginUrl, string token, string tokenSecret )
		{
			Condition.Requires( token ).IsNotNullOrEmpty();
			Condition.Requires( tokenSecret ).IsNotNullOrEmpty();

			LoginUrl = loginUrl;
			Token = token;
			TokenSecret = tokenSecret;
		}
	}

	/// <summary>
	///	This service is oriented on working with OAuth 1.0 credentials.
	/// You can easily get permanent credentials having only consumer key and secret.
	/// </summary>
	public class EtsyAuthenticationService : BaseService, IEtsyAuthenticationService
	{
		public EtsyAuthenticationService( string applicationKey, string sharedSecret, EtsyConfig config, Throttler throttler ) 
			: base( applicationKey, sharedSecret, config, throttler )
		{
		}

		/// <summary>
		///	Returns access token for making authorized API calls
		/// </summary>
		/// <returns></returns>
		public Task< OAuthCredentials > GetPermanentCredentials( string temporaryToken, string temporaryTokenSecret, string verifierCode )
		{
			Condition.Requires( temporaryToken ).IsNotNullOrEmpty();
			Condition.Requires( temporaryTokenSecret ).IsNotNullOrEmpty();
			Condition.Requires( verifierCode ).IsNotNullOrEmpty();

			var mark = Mark.CreateNew();

			var requestParameters = new Dictionary<string, string>
			{
				{ "oauth_token", temporaryToken },
				{ "oauth_verifier", verifierCode }
			};

			return Policy.HandleResult< OAuthCredentials >( credentials => credentials == null )
				.WaitAndRetryAsync( Config.RetryAttempts,
					retryCount => TimeSpan.FromSeconds( ActionPolicy.GetDelayBeforeNextAttempt( retryCount ) ),
					( entityRaw, timeSpan, retryCount, context ) =>
					{
						string retryDetails = CreateMethodCallInfo( EtsyEndPoint.GetAccessTokenUrl, mark, additionalInfo: this.AdditionalLogInfo() );
						EtsyLogger.LogTraceRetryStarted( timeSpan.Seconds, retryCount, retryDetails );
					})
				.ExecuteAsync( async () =>
				{
					OAuthCredentials credentials = null;
					string url = Config.ApiBaseUrl + EtsyEndPoint.GetAccessTokenUrl;

					try
					{
						var oauthParameters = Authenticator.GetOAuthRequestParameters( url, "GET", temporaryTokenSecret, requestParameters );
						url = Authenticator.GetUrl( url, oauthParameters );

						EtsyLogger.LogStarted( this.CreateMethodCallInfo( url, mark, additionalInfo : this.AdditionalLogInfo() ) );

						HttpResponseMessage response = await HttpClient.GetAsync( url ).ConfigureAwait( false );
						var result = response.Content.ReadAsStringAsync().Result;

						ThrowIfError( response, result );

						EtsyLogger.LogEnd( this.CreateMethodCallInfo( url, mark, methodResult: result.ToJson(), additionalInfo : this.AdditionalLogInfo() ) );

						var queryParams = Misc.ParseQueryParams( result );
						queryParams.TryGetValue( "oauth_token", out var token );
						queryParams.TryGetValue( "oauth_token_secret", out var tokenSecret );

						if (!( string.IsNullOrEmpty( token )
						       || string.IsNullOrEmpty( tokenSecret ) ))
							credentials = new OAuthCredentials( null, token, tokenSecret );
					}
					catch ( Exception exception )
					{
						var etsyException = new EtsyException( this.CreateMethodCallInfo( url, mark, additionalInfo : this.AdditionalLogInfo() ), exception );
						EtsyLogger.LogTraceException( etsyException );
					}

					return credentials;
				});
		}

		/// <summary>
		///	Returns temporary credentials and login url for customer
		/// </summary>
		/// <param name="scopes">Permissions</param>
		/// <param name="oauthCallback">Optional redirection URI where Etsy will redirect the user to after a successful login</param>
		/// <returns></returns>
		public Task< OAuthCredentials > GetTemporaryCredentials( string[] scopes, string oauthCallback = null )
		{
			Condition.Requires( scopes ).IsNotEmpty();

			var mark = Mark.CreateNew();

			var requestParameters = new Dictionary<string, string>
			{
				{ "scopes", string.Join(" ", scopes) },
				{ "oauth_callback", oauthCallback ?? "oob" }
			};

			return Policy.HandleResult<OAuthCredentials>( credentials => credentials == null )
				.WaitAndRetryAsync( Config.RetryAttempts,
					retryCount => TimeSpan.FromSeconds( ActionPolicy.GetDelayBeforeNextAttempt( retryCount ) ),
					(entityRaw, timeSpan, retryCount, context) =>
					{
						string retryDetails = CreateMethodCallInfo( EtsyEndPoint.GetRequestTokenUrl, mark, additionalInfo: this.AdditionalLogInfo() );
						EtsyLogger.LogTraceRetryStarted( timeSpan.Seconds, retryCount, retryDetails );
					} )
				.ExecuteAsync(async () =>
				{
					OAuthCredentials credentials = null;

					string absoluteUrl = Config.ApiBaseUrl + EtsyEndPoint.GetRequestTokenUrl;

					var oauthParameters = Authenticator.GetOAuthRequestParameters( absoluteUrl, "GET", null, requestParameters );
					string url = Authenticator.GetUrl( absoluteUrl, oauthParameters );

					try
					{
						EtsyLogger.LogStarted( this.CreateMethodCallInfo( url, mark, additionalInfo : this.AdditionalLogInfo() ) );

						HttpResponseMessage response = await HttpClient.GetAsync( url ).ConfigureAwait( false );

						var result = response.Content.ReadAsStringAsync().Result;

						EtsyLogger.LogEnd( this.CreateMethodCallInfo( url, mark, methodResult: result.ToJson(), additionalInfo : this.AdditionalLogInfo() ) );

						ThrowIfError( response, result );

						if ( !string.IsNullOrEmpty( result )
						     && result.IndexOf( "login_url", StringComparison.InvariantCulture ) > -1 )
						{
							string loginUrl = Uri.UnescapeDataString( result.Replace( "login_url=", "" ) );

							string[] temp = loginUrl.Split( '?' );

							// OAuthCallback might contain additional question marks
							if ( temp.Length >= 2 )
							{
								var queryParams = Misc.ParseQueryParams( temp[1] );
								queryParams.TryGetValue( "oauth_token", out var token );
								queryParams.TryGetValue( "oauth_token_secret", out var tokenSecret );

								if ( token != null && tokenSecret != null )
									credentials = new OAuthCredentials( loginUrl, token, tokenSecret );
							}
						}
					}
					catch ( Exception exception )
					{
						var etsyException = new EtsyException( this.CreateMethodCallInfo( url, mark, additionalInfo : this.AdditionalLogInfo() ), exception );
						EtsyLogger.LogTraceException( etsyException );
					}

					return credentials;
				});
		}
	}
}
