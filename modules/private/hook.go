// Copyright 2019 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package private

import (
	"code.gitea.io/gitea/modules/git"
	"code.gitea.io/gitea/modules/log"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"code.gitea.io/gitea/modules/setting"
	jsoniter "github.com/json-iterator/go"
)

// Git environment variables
const (
	GitAlternativeObjectDirectories = "GIT_ALTERNATE_OBJECT_DIRECTORIES"
	GitObjectDirectory              = "GIT_OBJECT_DIRECTORY"
	GitQuarantinePath               = "GIT_QUARANTINE_PATH"
	GitPushOptionCount              = "GIT_PUSH_OPTION_COUNT"
)

// GitPushOptions is a wrapper around a map[string]string
type GitPushOptions map[string]string

// GitPushOptions keys
const (
	GitPushOptionRepoPrivate  = "repo.private"
	GitPushOptionRepoTemplate = "repo.template"
)

// Bool checks for a key in the map and parses as a boolean
func (g GitPushOptions) Bool(key string, def bool) bool {
	if val, ok := g[key]; ok {
		if b, err := strconv.ParseBool(val); err == nil {
			return b
		}
	}
	return def
}

type ReadmeDiff struct {
	Path       string
	ChangesOut []string
}

// HookOptions represents the options for the Hook calls
type HookOptions struct {
	OldCommitIDs                    []string
	NewCommitIDs                    []string
	RefFullNames                    []string
	FileNames                       []string
	ReadmeDiffs                     []ReadmeDiff
	UserID                          int64
	UserName                        string
	GitObjectDirectory              string
	GitAlternativeObjectDirectories string
	GitQuarantinePath               string
	GitPushOptions                  GitPushOptions
	ProtectedBranchID               int64
	IsDeployKey                     bool
}

// HookPostReceiveResult represents an individual result from PostReceive
type HookPostReceiveResult struct {
	Results      []HookPostReceiveBranchResult
	RepoWasEmpty bool
	Err          string
}

// HookPostReceiveBranchResult represents an individual branch result from PostReceive
type HookPostReceiveBranchResult struct {
	Message bool
	Create  bool
	Branch  string
	URL     string
}

// HookPreReceive check whether the provided commits are allowed
func HookPreReceive(ownerName, repoName string, opts HookOptions) (int, string) {
	reqURL := setting.LocalURL + fmt.Sprintf("api/internal/hook/pre-receive/%s/%s",
		url.PathEscape(ownerName),
		url.PathEscape(repoName),
	)
	req := newInternalRequest(reqURL, "POST")
	req = req.Header("Content-Type", "application/json")
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonBytes, _ := json.Marshal(opts)
	req.Body(jsonBytes)
	req.SetTimeout(60*time.Second, time.Duration(60+len(opts.OldCommitIDs))*time.Second)
	resp, err := req.Response()
	if err != nil {
		return http.StatusInternalServerError, fmt.Sprintf("Unable to contact gitea: %v", err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, decodeJSONError(resp).Err
	}

	return http.StatusOK, ""
}

// HookPostReceive updates services and users
func HookPostReceive(ownerName, repoName string, opts HookOptions) (*HookPostReceiveResult, string) {
	reqURL := setting.LocalURL + fmt.Sprintf("api/internal/hook/post-receive/%s/%s",
		url.PathEscape(ownerName),
		url.PathEscape(repoName),
	)

	req := newInternalRequest(reqURL, "POST")
	req = req.Header("Content-Type", "application/json")
	req.SetTimeout(60*time.Second, time.Duration(60+len(opts.OldCommitIDs))*time.Second)
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	jsonBytes, _ := json.Marshal(opts)
	req.Body(jsonBytes)
	resp, err := req.Response()
	if err != nil {
		return nil, fmt.Sprintf("Unable to contact gitea: %v", err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, decodeJSONError(resp).Err
	}
	res := &HookPostReceiveResult{}
	_ = json.NewDecoder(resp.Body).Decode(res)

	return res, ""
}

// SetDefaultBranch will set the default branch to the provided branch for the provided repository
func SetDefaultBranch(ownerName, repoName, branch string) error {
	reqURL := setting.LocalURL + fmt.Sprintf("api/internal/hook/set-default-branch/%s/%s/%s",
		url.PathEscape(ownerName),
		url.PathEscape(repoName),
		url.PathEscape(branch),
	)
	req := newInternalRequest(reqURL, "POST")
	req = req.Header("Content-Type", "application/json")

	req.SetTimeout(60*time.Second, 60*time.Second)
	resp, err := req.Response()
	if err != nil {
		return fmt.Errorf("Unable to contact gitea: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Error returned from gitea: %v", decodeJSONError(resp).Err)
	}
	return nil
}

func HookPreReceiveExternal(ownerName string, repoName string, opts HookOptions) (int, string) {
	if setting.Git.EnablePreReceive {

		var revList string
		var err error

		if opts.OldCommitIDs[0] == "0000000000000000000000000000000000000000" {
			revList, err = git.NewCommand("rev-list", fmt.Sprintf("%s", opts.NewCommitIDs[0]), "--all").
				SetDescription(fmt.Sprintf("Reading revs %s", repoName)).
				RunInDir(fmt.Sprintf("%s/repositories/%s/%s.git", setting.Git.GitRoot, ownerName, repoName))
		} else {
			revList, err = git.NewCommand("rev-list", fmt.Sprintf("%s..%s", opts.OldCommitIDs[0], opts.NewCommitIDs[0])).
				SetDescription(fmt.Sprintf("Reading revs %s", repoName)).
				RunInDir(fmt.Sprintf("%s/repositories/%s/%s.git", setting.Git.GitRoot, ownerName, repoName))
		}

		if err != nil {
			log.Error("failed to parse ref-list: Stdout: %s\nError: %v", revList, err)
			return http.StatusForbidden, fmt.Sprintf("failed to parse ref-list: Stdout: %s\nError: %v", revList, err)
		}

		var names []string
		var readmeDiffs []ReadmeDiff

		entries := strings.Split(revList, "\n")

		for _, entry := range entries {

			if len(strings.TrimSpace(entry)) == 0 {
				continue
			}

			nameStatus, err := git.NewCommand("--no-pager", "log", "-1", "--name-only", "--pretty=format:", strings.TrimSpace(entry)).
				SetDescription(fmt.Sprintf("Parsing files for commit  %s", entry)).
				RunInDir(fmt.Sprintf("%s/repositories/%s/%s.git", setting.Git.GitRoot, ownerName, repoName))

			if err != nil {
				log.Error("Failed to parse  files for commit %s: Stdout: %s\nError: %v", entry, nameStatus, err)
				return http.StatusForbidden, fmt.Sprintf("Failed to parse files for commit %s: \nStdout: %s\nError: %v\nCommits:%v", entry, nameStatus, err, entries)
			}

			changes := strings.Split(nameStatus, "\n")

			for _, name := range changes {
				names = append(names, strings.TrimSpace(name))
			}
		}

		opts.FileNames = names
		opts.ReadmeDiffs = readmeDiffs

		reqURL := setting.Git.PreReceiveHookUrl + fmt.Sprintf("%s/%s",
			url.PathEscape(ownerName),
			url.PathEscape(repoName),
		)
		req := newInternalRequest(reqURL, "POST")
		req = req.Header("Content-Type", "application/json")
		json := jsoniter.ConfigCompatibleWithStandardLibrary
		jsonBytes, _ := json.Marshal(opts)
		req.Body(jsonBytes)
		req.SetTimeout(60*time.Second, time.Duration(60+len(opts.OldCommitIDs))*time.Second)
		resp, err := req.Response()
		if err != nil {
			return http.StatusInternalServerError, fmt.Sprintf("Unable to contact external pre-commit-hook: %v", err.Error())
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return resp.StatusCode, "Unexpected failure"
			}
			return resp.StatusCode, string(body)
		}
	}
	return http.StatusOK, ""
}

func HookPostReceiveExternal(ownerName, repoName string, opts HookOptions) (int, string) {
	if setting.Git.EnablePostReceive {

		var revList string
		var err error

		if opts.OldCommitIDs[0] == "0000000000000000000000000000000000000000" {
			revList, err = git.NewCommand("rev-list", fmt.Sprintf("%s", opts.NewCommitIDs[0]), "--all").
				SetDescription(fmt.Sprintf("Reading revs %s", repoName)).
				RunInDir(fmt.Sprintf("%s/repositories/%s/%s.git", setting.Git.GitRoot, ownerName, repoName))
		} else {
			revList, err = git.NewCommand("rev-list", fmt.Sprintf("%s..%s", opts.OldCommitIDs[0], opts.NewCommitIDs[0])).
				SetDescription(fmt.Sprintf("Reading revs %s", repoName)).
				RunInDir(fmt.Sprintf("%s/repositories/%s/%s.git", setting.Git.GitRoot, ownerName, repoName))
		}

		if err != nil {
			log.Error("failed to parse ref-list: Stdout: %s\nError: %v", revList, err)
			return http.StatusForbidden, fmt.Sprintf("failed to parse ref-list: Stdout: %s\nError: %v", revList, err)
		}

		var readmeDiffs []ReadmeDiff

		entries := strings.Split(revList, "\n")

		for _, entry := range entries {

			if len(strings.TrimSpace(entry)) == 0 {
				continue
			}

			nameStatus, err := git.NewCommand("--no-pager", "log", "-1", "--name-only", "--pretty=format:", strings.TrimSpace(entry)).
				SetDescription(fmt.Sprintf("Parsing files for commit  %s", entry)).
				RunInDir(fmt.Sprintf("%s/repositories/%s/%s.git", setting.Git.GitRoot, ownerName, repoName))

			if err != nil {
				log.Error("Failed to parse  files for commit %s: Stdout: %s\nError: %v", entry, nameStatus, err)
				return http.StatusForbidden, fmt.Sprintf("Failed to parse files for commit %s: \nStdout: %s\nError: %v\nCommits:%v", entry, nameStatus, err, entries)
			}

			changes := strings.Split(nameStatus, "\n")

			for _, name := range changes {

				if strings.Contains(strings.ToLower(name), "readme.md") {

					diff, err := git.NewCommand("--no-pager", "diff", "-G\"^[-+]?[0-9]+(\\.[0-9]+)?\\/[-+]?[0-9]+(\\.[0-9]+)?P$\"", strings.TrimSpace(entry), "--", strings.TrimSpace(name)).
						SetDescription(fmt.Sprintf("Parsing diffs in Readme %s", name)).
						RunInDir(fmt.Sprintf("%s/repositories/%s/%s.git", setting.Git.GitRoot, ownerName, repoName))

					if err != nil {
						log.Error("Failed to parse diff for readme %s: Stdout: %s\nError: %v", entry, nameStatus, err)
						return http.StatusForbidden, fmt.Sprintf("Failed to parse diff for commit %s: \nStdout: %s\nError: %v\nCommits:%v", entry, nameStatus, err, entries)
					}

					reg, err := regexp.Compile("^[-+]?[0-9]+(\\.[0-9]+)?/[-+]?[0-9]+(\\.[0-9]+)?P$")
					if err != nil {
						panic(err)
					}

					readmeDiffs = append(readmeDiffs, ReadmeDiff{name, reg.FindAllString(diff, -1)})
				}

			}
		}

		opts.ReadmeDiffs = readmeDiffs

		reqURL := setting.Git.PostReceiveHookUrl + fmt.Sprintf("%s/%s",
			url.PathEscape(ownerName),
			url.PathEscape(repoName),
		)

		req := newInternalRequest(reqURL, "POST")
		req = req.Header("Content-Type", "application/json")
		json := jsoniter.ConfigCompatibleWithStandardLibrary
		jsonBytes, _ := json.Marshal(opts)
		req.Body(jsonBytes)
		req.SetTimeout(60*time.Second, time.Duration(60+len(opts.OldCommitIDs))*time.Second)
		resp, err := req.Response()
		if err != nil {
			return http.StatusForbidden, fmt.Sprintf("Unable to contact external post-commit-hook: %v", err.Error())
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return http.StatusForbidden, "Unexpected failure"
			}
			return http.StatusForbidden, string(body)
		}
	}
	return http.StatusOK, ""
}
