﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using EtsyAccess.Services;
using FluentAssertions;
using NUnit.Framework;

namespace EtsyAccessTests
{
	public class AdminTest : BaseTest
	{
		[ Test ]
		public void GetShopInfoByName()
		{
			var shop = EtsyAdminService.GetShopInfo( ShopName ).GetAwaiter().GetResult();

			shop.Should().NotBeNull();
		}
	}
}