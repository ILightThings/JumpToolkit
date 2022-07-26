package jump_cred_tester

type credObject struct {
	UsernamesList       []string
	PasswordsList       []string
	DomainController    string
	ConcurrentUsers     int
	DelayBetweenGuesses int
	StopUserOnFound     bool
}

func main() {

}

//
//https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1#L369
//$behaviorversion = [int] $objDeDomain.Properties['msds-behavior-version'].item(0)
//    if ($behaviorversion -ge 3) <- Greater then windows 2003 dc

// (objectclass=msDS-PasswordSettings)" search for this to find password policies

//Write-Host -foregroundcolor "yellow" ("[*] A total of " + $PSOs.count + " Fine-Grained Password policies were found.`r`n")
//            foreach($entry in $PSOs)
//            {
//                # Selecting the lockout threshold, min pwd length, and which
//                # groups the fine-grained password policy applies to
//                $PSOFineGrainedPolicy = $entry | Select-Object -ExpandProperty Properties
//                $PSOPolicyName = $PSOFineGrainedPolicy.name
//                $PSOLockoutThreshold = $PSOFineGrainedPolicy.'msds-lockoutthreshold'
//                $PSOAppliesTo = $PSOFineGrainedPolicy.'msds-psoappliesto'
//                $PSOMinPwdLength = $PSOFineGrainedPolicy.'msds-minimumpasswordlength'
//                # adding lockout threshold to array for use later to determine which is the lowest.
//                $AccountLockoutThresholds += $PSOLockoutThreshold
//
//                Write-Host "[*] Fine-Grained Password Policy titled: $PSOPolicyName has a Lockout Threshold of $PSOLockoutThreshold attempts, minimum password length of $PSOMinPwdLength chars, and applies to $PSOAppliesTo.`r`n"
//            }

// Find all objects with msDS-PasswordSettings.
//Get the name of the object, $PSOFineGrainedPolicy.name
//Get the Lockoutthreshold 'msds-lockoutthreshold'
//Get applies to $PSOFineGrainedPolicy.'msds-psoappliesto'
//Get min pass length $PSOMinPwdLength

// Observation window is counted at the domain level
func FindDomainPassPolicies() {}
