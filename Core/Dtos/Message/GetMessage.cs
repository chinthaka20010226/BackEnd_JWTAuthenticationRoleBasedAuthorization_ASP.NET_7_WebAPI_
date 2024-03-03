namespace backend_dotnet7.Core.Dtos.Message
{
    public class GetMessage
    {
        public long Id { get; set; }
        public string SenderUserName { get; set; }
        public string ReceiverUserName { get; set; }
        public string Text { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}
