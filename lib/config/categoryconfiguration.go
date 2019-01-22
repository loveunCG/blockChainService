// Copyright (C) 2014 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package config

type CategoryConfiguration struct {
	Name              		string    `xml:"Name,attr" json:"Name"`
	SubCategories				[]string		`xml:"SubCategories" json:"SubCategories"`
}

func NewCategoryConfiguration(name string) CategoryConfiguration {
	f := CategoryConfiguration{
		Name:      name,
	}
	f.prepare()
	return f
}

func (cfg CategoryConfiguration) Copy() CategoryConfiguration {
	c := cfg
	c.SubCategories = make([]string, len(cfg.SubCategories))
	copy(c.SubCategories, cfg.SubCategories)
	return c
}

func (cfg *CategoryConfiguration) prepare() {
	if len(cfg.SubCategories) == 0 || len(cfg.SubCategories) == 1 && cfg.SubCategories[0] == "" {
		cfg.SubCategories = []string{"None"}
	}
}

type CategoryConfigurationList []CategoryConfiguration

func (l CategoryConfigurationList) Swap(a, b int) {
	l[a], l[b] = l[b], l[a]
}

func (l CategoryConfigurationList) Len() int {
	return len(l)
}
