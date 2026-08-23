Add-Type -AssemblyName System.IO.Compression.FileSystem

function Get-RealFileType {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('FullName')]
        [string]$Path
    )

    process {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            Write-Warning "File not found or is a directory: $Path"
            return
        }

        $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
        $currentExt   = [System.IO.Path]::GetExtension($resolvedPath)

        # Read the first 32 bytes for magic number detection
        try {
            $stream = [System.IO.File]::OpenRead($resolvedPath)
            $buffer = New-Object byte[] 32
            $bytesRead = $stream.Read($buffer, 0, 32)
            $stream.Close()
        }
        catch {
            Write-Warning "Could not read file: $resolvedPath ($($_.Exception.Message))"
            return
        }

        if ($bytesRead -eq 0) {
            return [PSCustomObject]@{
                File         = $resolvedPath
                CurrentExt   = if ($currentExt) { $currentExt } else { "(none)" }
                DetectedExt  = "(empty)"
                Category     = "Empty"
                Description  = "Empty File (0 bytes)"
                HexSignature = ""
            }
        }

        $hex = ($buffer[0..($bytesRead - 1)] | ForEach-Object { $_.ToString("X2") }) -join ""

        $cat  = "Unknown"
        $ext  = "Unknown"
        $desc = "Unrecognized Signature"

        # ----------------- 1. MODERN ZIP / OPENXML DEEP INSPECTION -----------------
        if ($hex -match "^504B0304") {
            $cat  = "Archive"
            $ext  = ".zip"
            $desc = "Standard ZIP Archive"

            try {
                $zipStream = [System.IO.File]::OpenRead($resolvedPath)
                $archive = New-Object System.IO.Compression.ZipArchive($zipStream, [System.IO.Compression.ZipArchiveMode]::Read)
                $entries = $archive.Entries | ForEach-Object { $_.FullName }
                $archive.Dispose()
                $zipStream.Close()

                if ($entries -match "^word/") {
                    $ext  = ".docx"
                    $cat  = "Document"
                    $desc = "Microsoft Word Document (OpenXML)"
                }
                elseif ($entries -match "^xl/") {
                    $ext  = ".xlsx"
                    $cat  = "Document"
                    $desc = "Microsoft Excel Spreadsheet (OpenXML)"
                }
                elseif ($entries -match "^ppt/") {
                    $ext  = ".pptx"
                    $cat  = "Document"
                    $desc = "Microsoft PowerPoint Presentation (OpenXML)"
                }
                elseif ($entries -match "AndroidManifest\.xml") {
                    $ext  = ".apk"
                    $cat  = "Package"
                    $desc = "Android Application Package"
                }
                elseif ($entries -match "^META-INF/MANIFEST\.MF") {
                    $ext  = ".jar"
                    $cat  = "Package"
                    $desc = "Java Archive"
                }
                elseif ($entries -match "mimetype") {
                    $ext  = ".epub / .odf"
                    $cat  = "Document"
                    $desc = "EPUB Book or OpenDocument File"
                }
            }
            catch {
                $desc = "ZIP Container (Corrupted or Encrypted)"
            }
        }

        # ----------------- 2. LEGACY OLE COMPOUND FILE (DOC/XLS/PPT) DEEP INSPECTION -----------------
        elseif ($hex -match "^D0CF11E0A1B11AE1") {
            $cat  = "Document"
            $ext  = ".doc / .xls / .ppt"
            $desc = "Legacy MS Office Binary Document (OLE CFB)"

            try {
                $oleStream = [System.IO.File]::OpenRead($resolvedPath)
                $readLength = [Math]::Min(16384, [int]$oleStream.Length)
                $oleBytes = New-Object byte[] $readLength
                [void]$oleStream.Read($oleBytes, 0, $readLength)
                $oleStream.Close()

                # Internal OLE directory names are encoded in UTF-16LE
                $oleText = [System.Text.Encoding]::Unicode.GetString($oleBytes)

                if ($oleText -match "WordDocument") {
                    $ext  = ".doc"
                    $desc = "Legacy Microsoft Word 97-2003 Document"
                }
                elseif ($oleText -match "Workbook|Book") {
                    $ext  = ".xls"
                    $desc = "Legacy Microsoft Excel 97-2003 Spreadsheet"
                }
                elseif ($oleText -match "PowerPoint Document|Current User") {
                    $ext  = ".ppt"
                    $desc = "Legacy Microsoft PowerPoint 97-2003 Presentation"
                }
                elseif ($oleText -match "__substg1.0_") {
                    $ext  = ".msg"
                    $desc = "Outlook Message Document"
                }
                elseif ($oleText -match "VisioDocument") {
                    $ext  = ".vsd"
                    $desc = "Legacy Microsoft Visio Drawing"
                }
            }
            catch {
                # Fall back to generic OLE
            }
        }

        # ----------------- 3. IMAGES -----------------
        elseif ($hex -match "^89504E470D0A1A0A")       { $ext = ".png";  $cat = "Image";    $desc = "PNG Image" }
        elseif ($hex -match "^FFD8FF")                 { $ext = ".jpg";  $cat = "Image";    $desc = "JPEG Image" }
        elseif ($hex -match "^47494638")               { $ext = ".gif";  $cat = "Image";    $desc = "GIF Image" }
        elseif ($hex -match "^424D")                   { $ext = ".bmp";  $cat = "Image";    $desc = "Windows Bitmap" }
        elseif ($hex -match "^52494646.{8}57454250")     { $ext = ".webp"; $cat = "Image";  $desc = "WebP Image" }
        elseif ($hex -match "^49492A00|^4D4D002A")     { $ext = ".tiff"; $cat = "Image";    $desc = "TIFF Image" }
        elseif ($hex -match "^00000100")               { $ext = ".ico";  $cat = "Image";    $desc = "Windows Icon" }
        elseif ($hex -match "^38425053")               { $ext = ".psd";  $cat = "Image";    $desc = "Photoshop Document" }

        # ----------------- 4. AUDIO & VIDEO -----------------
        elseif ($hex -match "^1A45DFA3")               { $ext = ".mkv / .webm"; $cat = "Video"; $desc = "Matroska / WebM Container" }
        elseif ($hex -match "^.{8}66747970")           { $ext = ".mp4";  $cat = "Video";    $desc = "MP4 / QuickTime Video" }
        elseif ($hex -match "^52494646.{8}41564920")     { $ext = ".avi";  $cat = "Video";    $desc = "AVI Video" }
        elseif ($hex -match "^52494646.{8}57415645")     { $ext = ".wav";  $cat = "Audio";    $desc = "WAV Audio" }
        elseif ($hex -match "^494433|^FFF[B|3|2]")     { $ext = ".mp3";  $cat = "Audio";    $desc = "MP3 Audio" }
        elseif ($hex -match "^664C6143")               { $ext = ".flac"; $cat = "Audio";    $desc = "FLAC Audio" }
        elseif ($hex -match "^4F676753")               { $ext = ".ogg";  $cat = "Audio/Video"; $desc = "Ogg Container" }
        elseif ($hex -match "^3026B2752266CF11")       { $ext = ".wmv / .wma"; $cat = "Audio/Video"; $desc = "Windows Media (ASF)" }

        # ----------------- 5. OTHER DOCUMENTS & DATA -----------------
        elseif ($hex -match "^25504446")               { $ext = ".pdf";  $cat = "Document"; $desc = "PDF Document" }
        elseif ($hex -match "^7B5C727466")             { $ext = ".rtf";  $cat = "Document"; $desc = "Rich Text Format" }
        elseif ($hex -match "^3C3F786D6C|^3C737667")   { $ext = ".xml / .svg"; $cat = "Data"; $desc = "XML / SVG Document" }
        elseif ($hex -match "^53514C69746520666F726D6174203300") { $ext = ".sqlite / .db"; $cat = "Database"; $desc = "SQLite 3 Database" }

        # ----------------- 6. OTHER ARCHIVES -----------------
        elseif ($hex -match "^377ABCAF271C")           { $ext = ".7z";   $cat = "Archive";  $desc = "7-Zip Archive" }
        elseif ($hex -match "^526172211A07")           { $ext = ".rar";  $cat = "Archive";  $desc = "RAR Archive" }
        elseif ($hex -match "^1F8B")                   { $ext = ".gz";   $cat = "Archive";  $desc = "GZIP Compressed Archive" }
        elseif ($hex -match "^425A68")                 { $ext = ".bz2";  $cat = "Archive";  $desc = "BZIP2 Compressed Archive" }
        elseif ($hex -match "^FD377A585A00")           { $ext = ".xz";   $cat = "Archive";  $desc = "XZ Archive" }

        # ----------------- 7. EXECUTABLES -----------------
        elseif ($hex -match "^4D5A")                   { $ext = ".exe / .dll"; $cat = "Executable"; $desc = "DOS/Windows Executable or DLL" }
        elseif ($hex -match "^7F454C46")               { $ext = ".elf";  $cat = "Executable"; $desc = "Linux ELF Binary" }
        elseif ($hex -match "^CAFEBABE")               { $ext = ".class / Mach-O"; $cat = "Executable"; $desc = "Java Class / Mach-O Binary" }

        # Output object
        [PSCustomObject]@{
            File         = $resolvedPath
            CurrentExt   = if ($currentExt) { $currentExt } else { "(none)" }
            DetectedExt  = $ext
            Category     = $cat
            Description  = $desc
            HexSignature = ($buffer[0..([Math]::Min(7, $bytesRead - 1))] | ForEach-Object { $_.ToString("X2") }) -join " "
        }
    }
}