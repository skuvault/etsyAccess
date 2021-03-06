﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using CuttingEdge.Conditions;
using EtsyAccess.Shared;

namespace EtsyAccess.Services.Authentication
{
	public class OAuthenticator
	{
		private readonly string _consumerKey;
		private readonly string _consumerSecret;
		private readonly string _token;
		private readonly string _tokenSecret;

		public OAuthenticator( string consumerKey, string consumerSecret ) : this( consumerKey, consumerSecret, null, null) 
		{ }

		public OAuthenticator( string consumerKey, string consumerSecret, string token, string tokenSecret )
		{
			Condition.Requires( consumerKey ).IsNotNullOrEmpty();
			Condition.Requires( consumerSecret ).IsNotNullOrEmpty();

			_token = token;
			_tokenSecret = tokenSecret;
			_consumerKey = consumerKey;
			_consumerSecret = consumerSecret;
		}

		/// <summary>
		///	Returns url with OAuth 1.0 query parameters
		/// </summary>
		/// <param name="url"></param>
		/// <param name="methodName"></param>
		/// <param name="extraRequestParameters"></param>
		/// <returns></returns>
		public string GetUriWithOAuthQueryParameters( string url, string methodName = "GET",  Dictionary<string, string> extraRequestParameters = null )
		{
			var oauthRequestParams = GetOAuthRequestParameters( url, methodName, _tokenSecret, extraRequestParameters );

			return GetUrl(url, oauthRequestParams);
		}

		/// <summary>
		///	Returns OAuth 1.0 request parameters with signature
		/// </summary>
		/// <param name="url"></param>
		/// <param name="method"></param>
		/// <param name="tokenSecret"></param>
		/// <param name="extraRequestParameters"></param>
		/// <returns></returns>
		public Dictionary< string, string > GetOAuthRequestParameters( string url, string method, string tokenSecret, Dictionary< string, string > extraRequestParameters )
		{
			// standard OAuth 1.0 request parameters
			var requestParameters = new Dictionary< string, string >
			{
				{ "oauth_consumer_key", _consumerKey },
				{ "oauth_nonce", GetRandomSessionNonce() },
				{ "oauth_signature_method", "HMAC-SHA1" },
				{ "oauth_timestamp", GetUtcEpochTime().ToString() },
				{ "oauth_version", "1.0" },
			};

			// if request token exists
			if ( !string.IsNullOrEmpty( _token ) )
				requestParameters.Add("oauth_token", _token);

			// extra query parameters
			if ( extraRequestParameters != null )
			{
				foreach( var keyValue in extraRequestParameters ) {
					if ( !requestParameters.ContainsKey( keyValue.Key ) )
					{
						requestParameters.Add( keyValue.Key, keyValue.Value );
					} 
					else
					{
						requestParameters[ keyValue.Key ] = keyValue.Value;
					}
				}
			}

			Uri uri = new Uri( url );
			string baseUrl = uri.Scheme + "://" + uri.Host + uri.LocalPath;

			// extra parameters can be placed also directly in the url
			var queryParams = Misc.ParseQueryParams( uri.Query );

			foreach ( var queryParam in queryParams )
			{
				if ( !requestParameters.ContainsKey( queryParam.Key ) )
					requestParameters.Add( queryParam.Key, queryParams[ queryParam.Key ] );
			}

			requestParameters.Remove( "oauth_signature" );

			string signature = GetOAuthSignature( baseUrl, method, tokenSecret, requestParameters );
			requestParameters.Add( "oauth_signature", signature );

			// if http method isn't GET all request parameters should be included in the request body
			if ( extraRequestParameters != null
			    && !method.ToUpper().Equals( "GET" ) )
			{
				foreach ( var keyValue in extraRequestParameters )
					requestParameters.Remove( keyValue.Key );
			}

			return requestParameters;
		}

		/// <summary>
		///	Returns signed request payload by using HMAC-SHA1
		/// </summary>
		/// <param name="url"></param>
		/// <param name="urlMethod"></param>
		/// <param name="tokenSecret"></param>
		/// <param name="requestParameters"></param>
		/// <returns></returns>
		private string GetOAuthSignature( string baseUrl, string urlMethod, string tokenSecret, Dictionary< string, string > requestParameters )
		{
			string signature = null;

			string urlEncoded = PercentEncodeData( baseUrl );
			string encodedParameters = PercentEncodeData( string.Join( "&",
				requestParameters.OrderBy( kv => kv.Key ).Select( item =>
					($"{ PercentEncodeData( item.Key ) }={ PercentEncodeData( item.Value ) }") ) ) );
			
			string baseString = $"{ urlMethod.ToUpper() }&{ urlEncoded }&{ encodedParameters }";

			HMACSHA1 hmacsha1 = new HMACSHA1( Encoding.ASCII.GetBytes( _consumerSecret + "&" + ( string.IsNullOrEmpty( tokenSecret ) ? "" : tokenSecret) ) );
			byte[] data = Encoding.ASCII.GetBytes( baseString );

			using (var stream = new MemoryStream( data ))
				signature = Convert.ToBase64String( hmacsha1.ComputeHash( stream ) );

			return signature;
		}

		/// <summary>
		///	Generates random nonce for each request
		/// </summary>
		/// <returns></returns>
		private string GetRandomSessionNonce()
		{
			return Guid.NewGuid().ToString().Replace( "-", "" ).Substring( 0, 11 ).ToUpper();
		}

		/// <summary>
		///	Returns url with query parameters
		/// </summary>
		/// <param name="url"></param>
		/// <param name="requestParameters"></param>
		/// <returns></returns>
		public string GetUrl( string url, Dictionary< string, string > requestParameters )
		{
			Uri uri = new Uri( url );
			string baseUrl = uri.Scheme + "://" + uri.Host + uri.LocalPath;

			var paramsBuilder = new StringBuilder();

			foreach ( var kv in requestParameters )
			{
				if ( paramsBuilder.Length > 0 )
					paramsBuilder.Append( "&" );

				paramsBuilder.Append( String.Format( "{0}={1}", kv.Key, kv.Value ) );
			}

			return baseUrl + "?" + paramsBuilder.ToString();
		}

		/// <summary>
		///	Custom implementation of URI components encoding for RFC 5849
		/// </summary>
		/// <param name="data"></param>
		/// <returns></returns>
		public string PercentEncodeData( string data )
		{
			string unreservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
			StringBuilder result = new StringBuilder();
			// percent encoding string should be produced by reading byte-by-byte to properly encode UTF-8 chars
			var rawData = Encoding.UTF8.GetBytes( data );

			foreach ( byte symbolByte in rawData ) {
				var symbol = (char)symbolByte;
				if ( unreservedChars.IndexOf(symbol) != -1 ) {
					result.Append( symbol );
				} else {
					result.Append('%' + String.Format("{0:X2}", (int)symbolByte));
				}
			}

			return result.ToString();
		}

		/// <summary>
		///	Returns Unix epoch (number of seconds elapsed since January 1, 1970)
		/// </summary>
		/// <returns></returns>
		private long GetUtcEpochTime()
		{
			return (int)( DateTime.UtcNow - new DateTime( 1970, 1, 1 ) ).TotalSeconds;
		}

	}
}
