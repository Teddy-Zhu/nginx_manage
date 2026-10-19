package components

// InspectRecords verifies existing preparation records without opening the
// worker, claiming recovery, downloading assets or changing any record.
func InspectRecords(dir string) error {
	m := &Manager{Dir: dir}
	entries, _, err := m.entries()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if len(name) < 6 || name[len(name)-5:] != ".json" {
			continue
		}
		if _, err = m.read(name[:len(name)-5]); err != nil {
			return err
		}
	}
	return nil
}
