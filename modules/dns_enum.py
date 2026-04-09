import dns.resolver
import dns.exception

def get_dns_records(domain):
    """
    استعلام جميع أنواع سجلات DNS مع تنظيف النصوص
    """
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    results = {}
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records = []
            
            for answer in answers:
                if record_type == "MX":
                    records.append({
                        "preference": answer.preference,
                        "exchange": str(answer.exchange).rstrip('.')
                    })
                elif record_type == "SOA":
                    records.append({
                        "mname": str(answer.mname).rstrip('.'),
                        "rname": str(answer.rname).rstrip('.'),
                        "serial": answer.serial,
                        "refresh": answer.refresh,
                        "retry": answer.retry,
                        "expire": answer.expire,
                        "minimum": answer.minimum
                    })
                elif record_type == "TXT":
                    # تنظيف TXT records
                    txt_string = ''.join([str(s) for s in answer.strings])
                    records.append(txt_string.strip('"'))
                else:
                    records.append(str(answer))
                    
            results[record_type] = records
            
        except dns.resolver.NoAnswer:
            results[record_type] = []
        except dns.resolver.NXDOMAIN:
            results[record_type] = []
        except Exception as e:
            results[record_type] = [f"Error: {str(e)}"]
    
    return results
