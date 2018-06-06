

private rule isTAR
{
	meta:
		Author = "Zahid Adeel (zahidadeelhashmat@gmail.com)"
		Description = "Identify TAR archive"
		Version = "0.1"
		
	strings:
		$magic = { 75 73 74 61 72 (00 30 30|20 20 00) }

	condition:
		
		$magic
}

private rule isZIP
{
	meta:
		Author = "Zahid Adeel (zahidadeelhashmat@gmail.com)"
		Description = "Identify ZIP archive"
		Version = "0.1"
		
	strings:
		$magic = { 50 4B 03 04 }

	condition:

		$magic
}


rule Zip_Slip
{
	meta:
		Author = "Zahid Adeel (zahidadeelhashmat@gmail.com)"
		Description = "Zip Slip Vulnerability (Arbitrary file write through archive extraction)"
		Reference = "https://github.com/snyk/zip-slip-vulnerability"
		Version = "0.1"
		
	strings:
		/*
		Zip-Slip exploits improper path validation bug in libraries to write arbitrary files. So, we need to check for reverse directory traversal signature which will be something like ../../../../../etc/passwd
		*/

		// directory traversal on Linux   	
		$zipSlipPayload1 = /(\x2e\x2e\x2f){2,}/
		
		// directory traversal on Windows
		$zipSlipPayload2 = /(\x2E\x2E\x5C){2,}/

	condition:
		(isTAR or isZIP) and (any of ($zipSlipPayload*))
		
} 
