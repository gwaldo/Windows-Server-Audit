#! /usr/bin/env perl 
 
# Enterprise Inventory / Audit 
# Gather vital stats from all servers in domain 
# Currently targets localhost if no servers are provided as arguments 
# .csv Output 
# Added LDAP 
# Iterates over multiple domains 
# Written by Waldo, gwaldo@gmail.com 
 
 
 
use strict; 
# Install these modules from CPAN 
use Win32::OLE('in'); 
use Net::Ping; 
use Net::LDAP; 
use Term::ReadKey; 
 
 
use constant wbemFlagReturnImmediately => 0x10; 
use constant wbemFlagForwardOnly => 0x20; 
 
 
# Allow for credentials to be input quietly 
my $arg = @ARGV; 
my $password = @ARGV[0]; 
if ($arg < 1) { 
    ReadMode('noecho'); 
    print "Password:\n"; 
    $password = ReadLine(0); 
    chomp $password; 
} 
 
 
#---Define the Target Domains--- 
my %domains = ( 
                "subdomain.domain.com"    => "DC=subdomain,DC=domain,DC=com", 
                "another.domain.com"    => "DC=another,DC=domain,DC=com", 
                "yomamma.jokes.com"        => "DC=yomamma,DC=jokes,DC=com", 
                "ranoutof.domains.com"    => "DC=ranoutof,DC=domains,DC=com", 
                ); 
 
 
 
while((my $key, my $value) = each(%domains)) { 
    my $baseDN            = $value; 
    my $domain            = $key; 
    my $searchFilter    = "(operatingSystem=Windows*Server*)"; 
    my $ldap; 
 
    print "$domain\n$baseDN\n\n\n"; 
     
    $ldap = Net::LDAP->new("$domain", port=>389, timeout=>30) or die $@; 
    #print "\$ldap is $ldap\n\n";    #diagprint 
    # Apparently you do need to specify credentials here. 
    $ldap->bind("CN=ScriptAdmin,OU=ServiceAccounts,OU=Users,DC=subdomain,DC=domain,DC=com", 
                password=>"$password" 
                ); 
 
    my $searchResults = $ldap->search(filter    =>"$searchFilter", 
                            base     => "$baseDN", 
                            scope    => "sub", 
                            attrs    => ['dn', 'name', 'lastLogonTimeStamp', 'operatingSystem'] 
                            ); 
 
    my @results        = $searchResults->entries; 
    my $count        = $searchResults->count; 
    #my @computers    =  
 
    #---GO FORTH!--- 
     
    print "TargetName,Hostname,Domain,IP,Manufacturer,Model,SerialNumber,WindowsVersion,Edition,Bitness,ServicePack,BuildNumber,Version\n"; 
 
    foreach my $result (@results) { 
        my $computer = $result->get_value("name"); 
        #---Test for connectivity--- 
        my $ping = Net::Ping->new() or die "Can't Create Ping Object.  Something is very wrong...\n"; 
        if (!$ping->ping($computer)) { 
            print "Cannot ping $computer.\n"; 
        } else { 
 
            #---Set our Namespaces--- 
            my $objWMIService = Win32::OLE->GetObject 
                ("winmgmts:\\\\$computer\\root\\CIMV2"); 
            if (!$objWMIService) {        # Thanks, Juan... 
                print "WMI connection to $computer failed.\n"; 
            } else { 
                my $col_System_Items = $objWMIService->ExecQuery("SELECT * FROM 
                    Win32_ComputerSystem", "WQL", 
                    wbemFlagReturnImmediately | wbemFlagForwardOnly); 
                my $col_OS_Items = $objWMIService->ExecQuery("SELECT * FROM 
                    Win32_OperatingSystem", "WQL", 
                    wbemFlagReturnImmediately | wbemFlagForwardOnly); 
                my $col_BIOS_Items = $objWMIService->ExecQuery("SELECT * FROM 
                    Win32_BIOS", "WQL", 
                    wbemFlagReturnImmediately | wbemFlagForwardOnly); 
                my $col_NET_Items = $objWMIService->ExecQuery("SELECT * FROM 
                    Win32_NetworkAdapterConfiguration", "WQL", 
                    wbemFlagReturnImmediately | wbemFlagForwardOnly); 
 
 
                #---Declaring Scoped Variables--- 
                #---Raw variables--- 
                my ($strName, $strDomain, $strManufacturer, $strModel, $strCaption, 
                $strServicePack, $strBuildNumber, $strVersion, $strSerialNumber, $strIP); 
                #---Derived Variables--- 
                my ($strWinVer, $strEdition, $strBitness, $strServerData); 
 
 
                #---Get our Data--- 
                foreach my $obj_System_Item (in $col_System_Items) { 
                # I've never used the 'in' keyword. Have you run this program? Does 'in 
                # $scalar' dereference the list reference inside the scalar? 
 
                # 'foreach' is just syntactical sugar. This line can simply be: 
                # for my $obj_System_Item (@$col_System_Items) 
                # --JCM 
                    $strName            = $obj_System_Item->{Name}; 
                    $strDomain            = $obj_System_Item->{Domain}; 
                    $strManufacturer    = $obj_System_Item->{Manufacturer}; 
                    $strModel            = $obj_System_Item->{Model}; 
                    $strModel            =~ s/\s+$//; #removes trailing spaces 
                } 
 
                foreach my $obj_OS_Item (in $col_OS_Items) { 
                    $strCaption         = $obj_OS_Item->{Caption}; 
                    $strServicePack        = $obj_OS_Item->{ServicePackMajorVersion}; 
                    $strBuildNumber        = $obj_OS_Item->{BuildNumber}; 
                    $strVersion            = $obj_OS_Item->{Version}; 
 
                } 
 
                foreach my $obj_BIOS_Item (in $col_BIOS_Items) { 
                    $strSerialNumber    = $obj_BIOS_Item->{SerialNumber}; 
                    $strSerialNumber    =~ s/\s+$//; #removes trailing spaces 
                } 
 
 
                foreach my $obj_NET_Item (in $col_NET_Items) { 
                    #my $ip = $obj_NET_Item->{IPAddress}; 
                    my $ip = join(",", (in $obj_NET_Item->{IPAddress})); 
                    if (($ip) && ($ip != '0.0.0.0')) 
                    { 
                        #print "IPAddress: " . join(",", (in $obj_NET_Item->{IPAddress})) . "\n"; 
                        #print "IPAddress: " . join(",", (in $ip)) . "\n"; 
                        $strIP            = $ip; 
                    } 
                } 
 
 
                #---Making Data Meaningful--- 
                #---OS--- 
                if ($strCaption =~/2008/) { 
                    $strWinVer = "Win2k8"; 
                } 
                elsif ($strCaption =~/2003/) { 
                    $strWinVer = "Win2k3"; 
                } 
                elsif ($strCaption =~/2000/) { 
                    $strWinVer = "Win2k"; 
                } 
                elsif ($strCaption =~/NT/) { 
                    $strWinVer = "WinNT"; 
                } 
                else { 
                    $strWinVer = "Unexpected Version"; 
                } 
 
                #---Edition--- 
                if ($strCaption =~/enterprise/i) { 
                    $strEdition = "Enterprise"; 
                } 
                elsif ($strCaption =~/datacenter/i) { 
                    $strEdition = "DataCenter"; 
                } 
                elsif ($strCaption =~/standard/i) { 
                    $strEdition = "Standard"; 
                } 
                elsif ($strCaption =~/Microsoft Windows 2000 Server/i) { 
                    $strEdition = ""; 
                } 
                elsif ($strCaption =~/advanced/i) { 
                    $strEdition = "Advanced"; 
                } 
                else { 
                    $strEdition = "Unexpected Edition"; 
                } 
 
                #---R2, or not to R2... That is the question--- 
                if ($strCaption =~/r2/i) { 
                    $strEdition = "R2_" . $strEdition; 
                } 
 
                #---Mind your Bitness--- 
                if ($strCaption =~/64/) { 
                    $strBitness = "64-bit"; 
                } else { 
                    $strBitness = "32-bit"; 
                } 
 
                #---Handling VMware "Hardware"--- 
                if ($strManufacturer =~/vmware/i) { 
                    $strManufacturer = "VMware"; 
                    #$strSerialNumber = substr($strSerialNumber, 7); 
                } 
 
 
 
                #---Gather Results--- 
                # I suppose I could do this in an array, but I don't know that it would get 
                # me anything.  This seems to be easier to read than an array index. 
                # Hopefully Future-Waldo will think this is crap code... 
                $strServerData =    "$computer," . 
                                    "$strName," . 
                                    "$strDomain," . 
                                    "$strIP," . 
                                    "$strManufacturer," . 
                                    "$strModel," . 
                                    "$strSerialNumber," . 
                                    "$strWinVer," . 
                                    "$strEdition," . 
                                    "$strBitness," . 
                                    "$strServicePack," . 
                                    "$strBuildNumber," . 
                                    "$strVersion"; 
 
                print "$strServerData\n"; 
                 
                #---Clean Up for Next Run, just in case...--- 
                ($strName, $strDomain, $strIP, $strManufacturer, $strModel,  
                    $strSerialNumber, $strWinVer, $strEdition, $strBitness,  
                    $strServicePack, $strBuildNumber, $strVersion) = ""; 
            } 
        } 
    } 
 
 
    #---Cleanup--- 
    $ldap->unbind(); 
 
} 
 

