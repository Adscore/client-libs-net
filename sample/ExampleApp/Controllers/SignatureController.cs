using AdScore.Signature;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using System;
using System.Linq;

namespace ExampleApp.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class SignatureController : ControllerBase
    {

        /// <summary>
        /// 
        /// </summary>
        /// <param name="signature">contains result.signature from the Adscore Javascript API</param>
        /// <returns></returns>
        [HttpGet("Verify")]
        public IActionResult Verify([FromQuery] string signature)
        {
            var userAgent = Request.Headers["User-Agent"].ToString();
            var unixTimestamp = Convert.ToInt64((DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalMilliseconds);
            var adscoreKey = "KEY_GOES_HERE";
            int? adscoreFlag;

            try
            {
                /*
			        The verify function parses and decodes the signature
			        Params:
				        Signature - from result.signature in Adscore Javascript API
				        Zone Response Key - from Zone Security Details page from Adscore Panel (go to Zones and click on the little key icon next to your zone name)
				        Visitor IP
				        Visitor User Agent
			        Returns an array with following keys:
				        Score - detection result, can be 0(ok), 3(junk), 6(proxy), 9(bot)
				        Verdict - detection result, can be 'ok', 'junk', 'proxy', 'bot'
				        IpAddress - IP address that was successfully used for verification
				        RequestTime - tiemstamp when the original full analysis was done by Adscore JavaScript API
				        SignatureTime - timestamp when the signature was generated
		        */
                var adscoreSigData = SignatureVerifier.Verify(signature, userAgent, "customer", adscoreKey, HttpContext.Connection.RemoteIpAddress.ToString());

                // In case signature was generated more than 1 minute ago, we assume the signature is expired and visitor is not validated (we use -1 as result code in such case in example below)
                adscoreFlag = ((unixTimestamp / 1000 - adscoreSigData.SignatureTime) > 60) ? -1 : adscoreSigData.Score;

                /*
                    In case the verify function returns error, it usually means that the signature is invalid. This can happen in following cases:
                        - Signature is empty or got truncated/malformed
                        - Visitor IP seen by our server is different from the IP seen by your server
                        - Visitor User Agent seen by our server is different from the User Agent seen by your server
                    In such case, we first try to verify the signature again, but using X-Forwarded-For instead of Visitor IP.
                    The reasoning behind it is that some proxy services like Google Data Saver can be trusted in the X-Forwarded-For
                */
                if (!string.IsNullOrEmpty(adscoreSigData.Error))
                {
                    var forwardedHeader = HttpContext.Request.Headers["X-Forwarded-For"];
                    if (!StringValues.IsNullOrEmpty(forwardedHeader))
                    {
                        // The X-Forwarded-For header can contain multiple IPs in case of proxy chain. Only the first one is extracted (as xfofoip)
                        var xfofoip = forwardedHeader.FirstOrDefault()?.Split(',').FirstOrDefault();
                        adscoreSigData = SignatureVerifier.Verify(signature, userAgent, "customer", adscoreKey, xfofoip);
                        adscoreFlag = ((unixTimestamp / 1000 - adscoreSigData.SignatureTime) > 60) ? -1 : adscoreSigData.Score;

                        if (!string.IsNullOrEmpty(adscoreSigData.Error))
                        {
                            // If there is X-Forwarded-For header, but verify with X-Forwarded-For IP has also failed, it means that the signature is invalid and there is nothing more to be done.
                            adscoreFlag = -2;
                        }
                    }
                    else
                    {
                        // If the first verify check has failed and there is no X-Forwarded-For header, then the signature is invalid and there is nothing more to be done.
                        adscoreFlag = -2;
                    }
                }
            }
            catch (Exception)
            {
                adscoreFlag = -2;
            }

            return Ok(new { adscoreFlag });
        }
    }
}
