// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/http/http_static.hpp"

#include "statusbar/toml/toml.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <ctime>

#include <sys/mman.h>
#include <sys/stat.h>

namespace statusbar::http {

namespace {

[[nodiscard]] auto imf_fixdate(time_t when) -> std::string
{
    // "Sun, 06 Nov 1994 08:49:37 GMT" — RFC 9110 §5.6.7.
    struct tm parts{};
    (void)gmtime_r(&when, &parts);
    char out[40];
    size_t const n = strftime(out, sizeof out, "%a, %d %b %Y %H:%M:%S GMT", &parts);
    return std::string{out, n};
}

[[nodiscard]] auto make_etag(uint64_t size, time_t mtime) -> std::string
{
    char out[48];
    int const n = snprintf(out, sizeof out, "\"%llx-%llx\"", (unsigned long long)size, (unsigned long long)mtime);
    return std::string{out, size_t(n)};
}

[[nodiscard]] auto manifest_error(char const* what, std::string_view detail) -> std::unexpected<std::error_code>
{
    // The load-time failure path may allocate and print — it IS startup.
    // NOLINTNEXTLINE(modernize-use-std-print): the diagnostic format is trivial
    fprintf(stderr, "http manifest: %s: %.*s\n", what, int(detail.size()), detail.data());
    return failure(std::errc::invalid_argument);
}

}  // namespace

StaticManifest::StaticManifest(StaticManifest&& other) noexcept
    : routes_{std::move(other.routes_)}
    , kept_fds_{std::move(other.kept_fds_)}
    , maps_{std::move(other.maps_)}
{
    other.maps_.clear();
}

auto StaticManifest::operator=(StaticManifest&& other) noexcept -> StaticManifest&
{
    if (this != &other) {
        release();
        routes_ = std::move(other.routes_);
        kept_fds_ = std::move(other.kept_fds_);
        maps_ = std::move(other.maps_);
        other.maps_.clear();
    }
    return *this;
}

StaticManifest::~StaticManifest()
{
    release();
}

void StaticManifest::release() noexcept
{
    for (auto const map : maps_) {
        if (!map.empty()) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): munmap wants the mutable pointer it returned
            ::munmap(const_cast<uint8_t*>(map.data()), map.size());
        }
    }
    maps_.clear();
}

auto StaticManifest::load(std::string const& manifest_path) -> StatusValue<StaticManifest>
{
    auto parsed = toml::parse_file(manifest_path);
    if (!parsed) {
        return manifest_error("cannot parse", manifest_path);
    }
    auto const dir_end = manifest_path.find_last_of('/');
    std::string const base_dir = dir_end == std::string::npos ? std::string{} : manifest_path.substr(0, dir_end + 1);

    auto const* routes_value = parsed->get("route");
    if (routes_value == nullptr || !routes_value->is_array()) {
        return manifest_error("no [[route]] entries in", manifest_path);
    }

    StaticManifest manifest;
    auto const& entries = *routes_value->as_array();
    for (size_t index = 0; index < entries.size(); ++index) {
        auto const& entry = entries[index];
        if (!entry.is_table()) {
            return manifest_error("route entry is not a table in", manifest_path);
        }
        auto const& table = *entry.as_table();
        auto get_string = [&](char const* key) -> std::string_view {
            auto const* value = table.get(key);
            return value != nullptr ? value->as_string().value_or(std::string_view{}) : std::string_view{};
        };
        StaticRoute route;
        route.uri = get_string("uri");
        route.file = get_string("file");
        route.content_type = get_string("type");
        route.cache_control = get_string("cache");
        bool const stream = [&] {
            auto const* value = table.get("stream");
            return value != nullptr && value->as_boolean().value_or(false);
        }();
        if (route.uri.empty() || route.uri.front() != '/' || route.file.empty() || route.content_type.empty()) {
            return manifest_error("route needs uri (starting with '/'), file, and type", route.uri);
        }
        std::string const path = route.file.front() == '/' ? route.file : base_dir + route.file;

        FileDescriptor fd{::open(path.c_str(), O_RDONLY | O_CLOEXEC)};
        if (!fd.valid()) {
            return manifest_error("cannot open", path);
        }
        struct stat st{};
        if (::fstat(fd.get(), &st) < 0 || !S_ISREG(st.st_mode)) {
            return manifest_error("not a regular file", path);
        }
        route.size = uint64_t(st.st_size);
        route.etag = make_etag(route.size, st.st_mtime);
        route.last_modified = imf_fixdate(st.st_mtime);

        bool mapped = false;
        if (!stream && route.size > 0) {
            void* const map = ::mmap(nullptr, size_t(route.size), PROT_READ, MAP_PRIVATE, fd.get(), 0);
            if (map != MAP_FAILED) {
                route.data = std::span<uint8_t const>{static_cast<uint8_t const*>(map), size_t(route.size)};
                manifest.maps_.push_back(route.data);
                mapped = true;
            }
        }
        if (!mapped && route.size > 0) {
            route.fd = fd.get();
            manifest.kept_fds_.push_back(std::move(fd));
        }
        // Zero-length files serve an empty body from neither source.
        manifest.routes_.push_back(std::move(route));
    }

    std::sort(
        manifest.routes_.begin(), manifest.routes_.end(), [](StaticRoute const& a, StaticRoute const& b) { return a.uri < b.uri; });
    for (size_t i = 1; i < manifest.routes_.size(); ++i) {
        if (manifest.routes_[i].uri == manifest.routes_[i - 1].uri) {
            return manifest_error("duplicate uri", manifest.routes_[i].uri);
        }
    }
    return manifest;
}

auto StaticManifest::find(std::string_view path) const noexcept -> StaticRoute const*
{
    auto const it = std::lower_bound(
        routes_.begin(), routes_.end(), path, [](StaticRoute const& r, std::string_view p) { return std::string_view{r.uri} < p; });
    if (it == routes_.end() || std::string_view{it->uri} != path) {
        return nullptr;
    }
    return &*it;
}

}  // namespace statusbar::http
