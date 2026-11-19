import Foundation

/// Finds the project our site grades for a Homebrew formula or cask.
///
/// First by repository: the formula's homepage and download URLs name a repository ("https://github.com/curl/curl/
/// releases/..." names github.com/curl/curl), and the index lists each project's repository. Then, for formulae whose
/// URLs name no repository (curl.se, openssl.org, python.org ...), by the small name map below.
public enum ProjectMatcher {
    /// Formula and cask names (without any `@version` suffix) whose URLs do not name the project's repository, and
    /// the project each one is. Every slug here exists in the index (checked by a test against a recorded index).
    /// A name is listed only when its versions are the project's versions; libgcrypt, for one, is not mapped to
    /// "GnuPG / libgcrypt", because GnuPG's fixed versions would be compared with libgcrypt's.
    public static let fallbackNames: [String: String] = [
        // the name differs from the slug
        "python": "cpython", "postgresql": "postgres", "bind": "bind9", "docker": "moby", "kubernetes-cli": "kubernetes",
        "jpeg-turbo": "libjpeg-turbo", "llama.cpp": "llama-cpp", "argocd": "argo-cd", "mysql-client": "mysql",
        // the same name as the slug
        "openssl": "openssl", "node": "node", "go": "go", "ruby": "ruby", "php": "php", "openjdk": "openjdk", "rust": "rust",
        "llvm": "llvm", "sqlite": "sqlite", "curl": "curl", "git": "git", "openssh": "openssh", "gnupg": "gnupg",
        "gnutls": "gnutls", "wolfssl": "wolfssl", "mbedtls": "mbedtls", "krb5": "krb5", "libssh": "libssh",
        "libssh2": "libssh2", "nginx": "nginx", "httpd": "httpd", "haproxy": "haproxy", "unbound": "unbound",
        "squid": "squid", "openvpn": "openvpn", "samba": "samba", "freerdp": "freerdp", "wireshark": "wireshark",
        "tomcat": "tomcat", "envoy": "envoy", "qemu": "qemu", "vim": "vim", "binutils": "binutils", "sudo": "sudo",
        "libxml2": "libxml2", "expat": "expat", "zlib": "zlib", "xz": "xz", "libarchive": "libarchive", "ffmpeg": "ffmpeg",
        "imagemagick": "imagemagick", "ghostscript": "ghostscript", "libtiff": "libtiff", "libpng": "libpng",
        "poppler": "poppler", "freetype": "freetype", "pcre2": "pcre2", "redis": "redis", "mysql": "mysql",
        "mariadb": "mariadb", "helm": "helm", "etcd": "etcd", "containerd": "containerd", "runc": "runc",
        "grafana": "grafana", "prometheus": "prometheus", "ollama": "ollama", "gitea": "gitea", "jenkins": "jenkins",
        "electron": "electron",
    ]

    /// The project for this formula or cask, or nil.
    public static func project(for item: HomebrewItem, in index: PublicIndex) -> PublicIndex.Project? {
        for url in item.urls {
            if let p = repositoryKeys(of: url).lazy.compactMap(index.project(repo:)).first { return p }
        }
        let base = item.name.split(separator: "@", maxSplits: 1).first.map(String.init) ?? item.name
        return fallbackNames[base].flatMap(index.project(slug:))
    }

    /// Candidate repository keys a URL names, most specific first: "https://github.com/a/b/archive/v1.tar.gz" gives
    /// "github.com/a/b/archive/v1.tar.gz", ..., "github.com/a/b", "github.com/a". Lowercase, without "www." or ".git".
    public static func repositoryKeys(of url: String) -> [String] {
        guard let c = URLComponents(string: url.trimmingCharacters(in: .whitespaces)),
              let scheme = c.scheme?.lowercased(), ["http", "https", "git"].contains(scheme),
              var host = c.host?.lowercased(), !host.isEmpty else { return [] }
        if host.hasPrefix("www.") { host.removeFirst(4) }
        var parts = c.path.split(separator: "/").map { $0.lowercased() }
        if let last = parts.last, last.hasSuffix(".git") { parts[parts.count - 1] = String(last.dropLast(4)) }
        parts = parts.filter { !$0.isEmpty && $0 != "-" }.prefix(8).map { $0 }       // GitLab's "/-/archive/..." marker
        return (1...max(parts.count, 1)).reversed().compactMap { n in
            n <= parts.count ? ([host] + parts.prefix(n)).joined(separator: "/") : nil
        }
    }
}
