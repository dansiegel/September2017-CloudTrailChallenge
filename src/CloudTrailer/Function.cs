using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Amazon.IdentityManagement;
using Amazon.IdentityManagement.Model;
using Amazon.Lambda.Core;
using Amazon.Lambda.SNSEvents;
using Amazon.S3;
using Amazon.SimpleNotificationService;
using Amazon.SimpleNotificationService.Model;
using CloudTrailer.Models;
using Newtonsoft.Json;


// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace CloudTrailer
{
    public class Function
    {
        private static readonly byte[] GZipHeaderBytes = {0x1f, 0x8b};
//        private static readonly byte[] GZipHeaderBytes = {0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 4, 0};

        private IAmazonS3 S3Client { get; }
        private IAmazonSimpleNotificationService SnsClient { get; }
        private IAmazonIdentityManagementService IamClient { get; }
        private static string AlertTopicArn => Environment.GetEnvironmentVariable("AlertTopicArn");

        /// <summary>
        /// Default constructor. This constructor is used by Lambda to construct the instance. When invoked in a Lambda environment
        /// the AWS credentials will come from the IAM role associated with the function and the AWS region will be set to the
        /// region the Lambda function is executed in.
        /// </summary>
        public Function()
        {
            S3Client = new AmazonS3Client();
            SnsClient = new AmazonSimpleNotificationServiceClient();
            IamClient = new AmazonIdentityManagementServiceClient();
        }

        public async Task FunctionHandler(SNSEvent evnt, ILambdaContext context)
        {
            // ### Level 1 - Create New Trail and Configure Lambda
            context.Logger.LogLine(JsonConvert.SerializeObject(evnt));

            // ### Level 2 - Retrieve Logs from S3
            var message = JsonConvert.DeserializeObject<CloudTrailMessage>(evnt.Records.First().Sns.Message);
            LambdaLogger.Log($"S3 Bucket: {message.S3Bucket}");
            LambdaLogger.Log($"S3 Object Key: {message.S3ObjectKey.First()}");
            var objectResponse = await S3Client.GetObjectAsync(message.S3Bucket, message.S3ObjectKey.First());
            var data = ReadFully(objectResponse.ResponseStream);
            var records = await ExtractCloudTrailRecordsAsync(context.Logger, data);
            foreach(var record in records.Records)
            {
                LambdaLogger.Log("Another FooBar record");
                LambdaLogger.Log(JsonConvert.SerializeObject(record));
                //LambdaLogger.Log($"{record.EventName}: {record.EventTime} - {record.SourceIpAddress}");
            }

            // ### Level 3 - Filter for specific events and send alerts
            var alerts = records.Records.Where(r => r.EventName == "CreateUser" && r.RequestParameters.Any(p => p.Key == "userName" && p.Value.ToString().StartsWith("foo", StringComparison.OrdinalIgnoreCase)));

            if(alerts.Any())
            {
                var response = await SnsClient.PublishAsync("arn:aws:sns:us-west-2:481999251613:FooBar", "People be creating some Foo users...");
                
                LambdaLogger.Log("Send Sns Message");
                // ### Boss level - Take mitigating action
                await BossAsync(alerts);
            }
            else
            {
                LambdaLogger.Log("No alerts were found this time... that was close...");
            }

        }

        private async Task BossAsync(IEnumerable<CloudTrailEvent> cloudTrailEvents)
        {
            foreach(var cloudTrailEvent in cloudTrailEvents)
            {
                var userName = cloudTrailEvent.RequestParameters.FirstOrDefault(p => p.Key == "userName").Value.ToString();
                try
                {
                    var response = await IamClient.DeleteUserAsync(new DeleteUserRequest(userName));
                    var message = $"Delete user: {userName} - Status: {response.HttpStatusCode}";
                    LambdaLogger.Log(message);
                    await SnsClient.PublishAsync("arn:aws:sns:us-west-2:481999251613:FooBar", message);
                }
                catch(AggregateException ae)
                {
                    LambdaLogger.Log(ae.Message);
                    await SnsClient.PublishAsync("arn:aws:sns:us-west-2:481999251613:FooBar", $"Error deleting {userName}: {ae.Message}");
                }
                catch(Exception e)
                {
                    LambdaLogger.Log($"{e.GetType().Name} - {e.Message}");
                    await SnsClient.PublishAsync("arn:aws:sns:us-west-2:481999251613:FooBar", $"An unexpected error occurred while deleting {userName}: {e.Message}");
                }
            }
        }


        private async Task<CloudTrailRecords> ExtractCloudTrailRecordsAsync(ILambdaLogger logger, byte[] input)
        {
            var appearsGzipped = ResponseAppearsGzipped(input);
            logger.LogLine($"Input appears to be gzipped: {appearsGzipped}");
            if (appearsGzipped)
            {
                using (var contents = new MemoryStream())
                using (var gz = new GZipStream(new MemoryStream(input), CompressionMode.Decompress))
                {
                    await gz.CopyToAsync(contents);
                    input = contents.ToArray();
                }
            }

            var serializedRecords = Encoding.UTF8.GetString(input);
            logger.Log(serializedRecords);
            return JsonConvert.DeserializeObject<CloudTrailRecords>(serializedRecords);

            bool ResponseAppearsGzipped(byte[] bytes)
            {
                var header = new byte[GZipHeaderBytes.Length];
                Array.Copy(bytes, header, header.Length);
                return header.SequenceEqual(GZipHeaderBytes);
            }
        }

        // FROM: https://stackoverflow.com/questions/221925/creating-a-byte-array-from-a-stream
        public static byte[] ReadFully(Stream input)
        {
            byte[] buffer = new byte[16*1024];
            using (MemoryStream ms = new MemoryStream())
            {
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ms.Write(buffer, 0, read);
                }
                return ms.ToArray();
            }
        }
    }
}