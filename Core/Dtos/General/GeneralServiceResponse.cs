﻿namespace backend_dotnet7.Core.Dtos.General
{
    public class GeneralServiceResponse
    {
        public bool IsSucceed { get; set; }
        public int StatusCode { get; set; }
        public string Message { get; set; }
    }
}
