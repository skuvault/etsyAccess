﻿using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CuttingEdge.Conditions;
using EtsyAccess.Exceptions;
using EtsyAccess.Shared;
using EtsyAccess.Models;
using EtsyAccess.Models.Configuration;

namespace EtsyAccess.Services.Orders
{
	public class EtsyOrdersService : BaseService, IEtsyOrdersService
	{
		public EtsyOrdersService( EtsyConfig config ) : base( config )
		{
		}

		/// <summary>
		///	Returns receipts that were changed in the specified period in asynchronous manner
		/// </summary>
		/// <param name="startDate"></param>
		/// <param name="endDate"></param>
		/// <returns></returns>
		public async Task< IEnumerable< Receipt > > GetOrdersAsync( DateTime startDate, DateTime endDate )
		{
			Condition.Requires( startDate ).IsLessThan( endDate );

			var mark = Mark.CreateNew();
			IEnumerable< Receipt > response = null;

			long minLastModified = startDate.FromUtcTimeToEpoch();
			long maxLastModified = endDate.FromUtcTimeToEpoch();

			string url = String.Format( EtsyEndPoint.GetReceiptsUrl + "&min_last_modified={1}&max_last_modified={2}", Config.ShopId,
				minLastModified, maxLastModified );

			try
			{
				EtsyLogger.LogStarted( this.CreateMethodCallInfo( url, mark, additionalInfo : this.AdditionalLogInfo() ) );

				response = await base.GetEntitiesAsync< Receipt >( url, mark: mark ).ConfigureAwait( false );

				EtsyLogger.LogEnd( this.CreateMethodCallInfo( url, mark, methodResult: response.ToJson(), additionalInfo : this.AdditionalLogInfo() ) );
			}
			catch ( Exception exception )
			{
				var etsyException = new EtsyException( this.CreateMethodCallInfo( url, mark, additionalInfo : this.AdditionalLogInfo() ), exception );
				EtsyLogger.LogTraceException( etsyException );
				throw etsyException;
			}

			return response;
		}

		/// <summary>
		///	Returns receipts that were changed in the specified period
		/// </summary>
		/// <param name="startDate"></param>
		/// <param name="endDate"></param>
		/// <returns></returns>
		IEnumerable< Receipt > IEtsyOrdersService.GetOrders( DateTime startDate, DateTime endDate)
		{
			return GetOrdersAsync( startDate, endDate ).GetAwaiter().GetResult();
		}
	}
}