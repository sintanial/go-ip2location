package ip2location

import (
	"os"
	"bytes"
	"encoding/binary"
	"math/big"
	"strconv"
	"net"
	"github.com/go-errors/errors"
	"io"
	"strings"
)

const ApiVersion string = "8.0.3"

var countryPosition = [25]uint8{0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
var regionPosition = [25]uint8{0, 0, 0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3}
var cityPosition = [25]uint8{0, 0, 0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4}
var ispPosition = [25]uint8{0, 0, 3, 0, 5, 0, 7, 5, 7, 0, 8, 0, 9, 0, 9, 0, 9, 0, 9, 7, 9, 0, 9, 7, 9}
var latitudePosition = [25]uint8{0, 0, 0, 0, 0, 5, 5, 0, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5}
var longitudePosition = [25]uint8{0, 0, 0, 0, 0, 6, 6, 0, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6}
var domainPosition = [25]uint8{0, 0, 0, 0, 0, 0, 0, 6, 8, 0, 9, 0, 10, 0, 10, 0, 10, 0, 10, 8, 10, 0, 10, 8, 10}
var zipcodePosition = [25]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 7, 7, 7, 0, 7, 7, 7, 0, 7, 0, 7, 7, 7, 0, 7}
var timezonePosition = [25]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 7, 8, 8, 8, 7, 8, 0, 8, 8, 8, 0, 8}
var netspeedPosition = [25]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 11, 0, 11, 8, 11, 0, 11, 0, 11, 0, 11}
var iddcodePosition = [25]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 12, 0, 12, 0, 12, 9, 12, 0, 12}
var areacodePosition = [25]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 13, 0, 13, 0, 13, 10, 13, 0, 13}
var weatherstationcodePosition = [25]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 14, 0, 14, 0, 14, 0, 14}
var weatherstationnamePosition = [25]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 15, 0, 15, 0, 15, 0, 15}
var mccPosition = [25]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 16, 0, 16, 9, 16}
var mncPosition = [25]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 17, 0, 17, 10, 17}
var mobilebrandPosition = [25]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 18, 0, 18, 11, 18}
var elevationPosition = [25]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 19, 0, 19}
var usagetypePosition = [25]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 20}

var maxIPv4Range = big.NewInt(4294967295)
var maxIPv6Range = big.NewInt(0)

func init() {
	maxIPv6Range.SetString("340282366920938463463374607431768211455", 10)
}

const CountryCodeField uint32 = 0x00001
const CountryNameField uint32 = 0x00002
const RegionField uint32 = 0x00004
const CityField uint32 = 0x00008
const IspField uint32 = 0x00010
const LatitudeField uint32 = 0x00020
const LongitudeField uint32 = 0x00040
const DomainField uint32 = 0x00080
const ZipCodeField uint32 = 0x00100
const TimezoneField uint32 = 0x00200
const NetSpeedField uint32 = 0x00400
const IddCodeField uint32 = 0x00800
const AreaCodeField uint32 = 0x01000
const WeatherStationCodeField uint32 = 0x02000
const WeatherStationNameField uint32 = 0x04000
const MccField uint32 = 0x08000
const MncField uint32 = 0x10000
const MobileBrandField uint32 = 0x20000
const ElevationField uint32 = 0x40000
const UsageTypeField uint32 = 0x80000

const AllField uint32 = CountryCodeField | CountryNameField | RegionField | CityField | IspField | LatitudeField | LongitudeField | DomainField | ZipCodeField | TimezoneField | NetSpeedField | IddCodeField | AreaCodeField | WeatherStationCodeField | WeatherStationNameField | MccField | MncField | MobileBrandField | ElevationField | UsageTypeField

var ErrInvalidIpAddress = errors.New("invalid ip address")

type Record struct {
	CountryCode        string
	CountryName        string
	Region             string
	City               string
	Isp                string
	Latitude           float32
	Longitude          float32
	Domain             string
	ZipCode            string
	TimeZone           string
	NetSpeed           string
	IddCode            string
	AreaCode           string
	WeatherStationCode string
	WeatherStationName string
	Mcc                string
	Mnc                string
	MobileBrand        string
	Elevation          float32
	UsageType          string
}

type dbmeta struct {
	databasetype      uint8
	databasecolumn    uint8
	databaseday       uint8
	databasemonth     uint8
	databaseyear      uint8
	ipv4databasecount uint32
	ipv4databaseaddr  uint32
	ipv6databasecount uint32
	ipv6databaseaddr  uint32
	ipv4indexbaseaddr uint32
	ipv6indexbaseaddr uint32
	ipv4columnsize    uint32
	ipv6columnsize    uint32
}

type fieldsEnabled struct {
	country            bool
	region             bool
	city               bool
	isp                bool
	domain             bool
	zipcode            bool
	latitude           bool
	longitude          bool
	timezone           bool
	netspeed           bool
	iddcode            bool
	areacode           bool
	weatherstationcode bool
	weatherstationname bool
	mcc                bool
	mnc                bool
	mobilebrand        bool
	elevation          bool
	usagetype          bool
}

type positionsOffset struct {
	country            uint32
	region             uint32
	city               uint32
	isp                uint32
	domain             uint32
	zipcode            uint32
	latitude           uint32
	longitude          uint32
	timezone           uint32
	netspeed           uint32
	iddcode            uint32
	areacode           uint32
	weatherstationcode uint32
	weatherstationname uint32
	mcc                uint32
	mnc                uint32
	mobilebrand        uint32
	elevation          uint32
	usagetype          uint32
}

type Reader struct {
	r    io.ReaderAt
	meta dbmeta

	fieldsEnabled   fieldsEnabled
	positionsOffset positionsOffset
}

func FromBytes(b []byte) (*Reader, error) {
	return FromReader(bytes.NewReader(b))
}

func FromFile(fpath string) (*Reader, error) {
	f, err := os.Open(fpath)
	if err != nil {
		return nil, err
	}

	return FromReader(f)
}

func FromReader(r io.ReaderAt) (*Reader, error) {
	m := dbmeta{}
	var err error
	if m.databasetype, err = readuint8(r, 1); err != nil {
		return nil, err
	}
	if m.databasecolumn, err = readuint8(r, 2); err != nil {
		return nil, err
	}
	if m.databaseyear, err = readuint8(r, 3); err != nil {
		return nil, err
	}
	if m.databasemonth, err = readuint8(r, 4); err != nil {
		return nil, err
	}
	if m.databaseday, err = readuint8(r, 5); err != nil {
		return nil, err
	}
	if m.ipv4databasecount, err = readuint32(r, 6); err != nil {
		return nil, err
	}
	if m.ipv4databaseaddr, err = readuint32(r, 10); err != nil {
		return nil, err
	}
	if m.ipv6databasecount, err = readuint32(r, 14); err != nil {
		return nil, err
	}
	if m.ipv6databaseaddr, err = readuint32(r, 18); err != nil {
		return nil, err
	}
	if m.ipv4indexbaseaddr, err = readuint32(r, 22); err != nil {
		return nil, err
	}
	if m.ipv6indexbaseaddr, err = readuint32(r, 26); err != nil {
		return nil, err
	}
	m.ipv4columnsize = uint32(m.databasecolumn << 2)              // 4 bytes each column
	m.ipv6columnsize = uint32(16 + ((m.databasecolumn - 1) << 2)) // 4 bytes each column, except IPFrom column which is 16 bytes

	dbr := &Reader{
		r:    r,
		meta: m,
	}

	dbt := m.databasetype

	// since both IPv4 and IPv6 use 4 bytes for the below columns, can just do it once here
	if countryPosition[dbt] != 0 {
		dbr.positionsOffset.country = uint32(countryPosition[dbt]-1) << 2
		dbr.fieldsEnabled.country = true
	}
	if regionPosition[dbt] != 0 {
		dbr.positionsOffset.region = uint32(regionPosition[dbt]-1) << 2
		dbr.fieldsEnabled.region = true
	}
	if cityPosition[dbt] != 0 {
		dbr.positionsOffset.city = uint32(cityPosition[dbt]-1) << 2
		dbr.fieldsEnabled.city = true
	}
	if ispPosition[dbt] != 0 {
		dbr.positionsOffset.isp = uint32(ispPosition[dbt]-1) << 2
		dbr.fieldsEnabled.isp = true
	}
	if domainPosition[dbt] != 0 {
		dbr.positionsOffset.domain = uint32(domainPosition[dbt]-1) << 2
		dbr.fieldsEnabled.domain = true
	}
	if zipcodePosition[dbt] != 0 {
		dbr.positionsOffset.zipcode = uint32(zipcodePosition[dbt]-1) << 2
		dbr.fieldsEnabled.zipcode = true
	}
	if latitudePosition[dbt] != 0 {
		dbr.positionsOffset.latitude = uint32(latitudePosition[dbt]-1) << 2
		dbr.fieldsEnabled.latitude = true
	}
	if longitudePosition[dbt] != 0 {
		dbr.positionsOffset.longitude = uint32(longitudePosition[dbt]-1) << 2
		dbr.fieldsEnabled.longitude = true
	}
	if timezonePosition[dbt] != 0 {
		dbr.positionsOffset.timezone = uint32(timezonePosition[dbt]-1) << 2
		dbr.fieldsEnabled.timezone = true
	}
	if netspeedPosition[dbt] != 0 {
		dbr.positionsOffset.netspeed = uint32(netspeedPosition[dbt]-1) << 2
		dbr.fieldsEnabled.netspeed = true
	}
	if iddcodePosition[dbt] != 0 {
		dbr.positionsOffset.iddcode = uint32(iddcodePosition[dbt]-1) << 2
		dbr.fieldsEnabled.iddcode = true
	}
	if areacodePosition[dbt] != 0 {
		dbr.positionsOffset.areacode = uint32(areacodePosition[dbt]-1) << 2
		dbr.fieldsEnabled.areacode = true
	}
	if weatherstationcodePosition[dbt] != 0 {
		dbr.positionsOffset.weatherstationcode = uint32(weatherstationcodePosition[dbt]-1) << 2
		dbr.fieldsEnabled.weatherstationcode = true
	}
	if weatherstationnamePosition[dbt] != 0 {
		dbr.positionsOffset.weatherstationname = uint32(weatherstationnamePosition[dbt]-1) << 2
		dbr.fieldsEnabled.weatherstationname = true
	}
	if mccPosition[dbt] != 0 {
		dbr.positionsOffset.mcc = uint32(mccPosition[dbt]-1) << 2
		dbr.fieldsEnabled.mcc = true
	}
	if mncPosition[dbt] != 0 {
		dbr.positionsOffset.mnc = uint32(mncPosition[dbt]-1) << 2
		dbr.fieldsEnabled.mnc = true
	}
	if mobilebrandPosition[dbt] != 0 {
		dbr.positionsOffset.mobilebrand = uint32(mobilebrandPosition[dbt]-1) << 2
		dbr.fieldsEnabled.mobilebrand = true
	}
	if elevationPosition[dbt] != 0 {
		dbr.positionsOffset.elevation = uint32(elevationPosition[dbt]-1) << 2
		dbr.fieldsEnabled.elevation = true
	}
	if usagetypePosition[dbt] != 0 {
		dbr.positionsOffset.usagetype = uint32(usagetypePosition[dbt]-1) << 2
		dbr.fieldsEnabled.usagetype = true
	}

	return dbr, nil
}

// get IP type and calculate IP number; calculates index too if exists
func (r *Reader) checkip(ip string) (iptype uint32, ipnum *big.Int, ipindex uint32) {
	iptype = 0
	ipnum = big.NewInt(0)
	ipnumtmp := big.NewInt(0)
	ipindex = 0
	ipaddress := net.ParseIP(ip)

	if ipaddress != nil {
		v4 := ipaddress.To4()

		if v4 != nil {
			iptype = 4
			ipnum.SetBytes(v4)
		} else {
			v6 := ipaddress.To16()

			if v6 != nil {
				iptype = 6
				ipnum.SetBytes(v6)
			}
		}
	}
	if iptype == 4 {
		if r.meta.ipv4indexbaseaddr > 0 {
			ipnumtmp.Rsh(ipnum, 16)
			ipnumtmp.Lsh(ipnumtmp, 3)
			ipindex = uint32(ipnumtmp.Add(ipnumtmp, big.NewInt(int64(r.meta.ipv4indexbaseaddr))).Uint64())
		}
	} else if iptype == 6 {
		if r.meta.ipv6indexbaseaddr > 0 {
			ipnumtmp.Rsh(ipnum, 112)
			ipnumtmp.Lsh(ipnumtmp, 3)
			ipindex = uint32(ipnumtmp.Add(ipnumtmp, big.NewInt(int64(r.meta.ipv6indexbaseaddr))).Uint64())
		}
	}
	return
}

// read byte
func readuint8(r io.ReaderAt, pos int64) (uint8, error) {
	data := make([]byte, 1)
	if _, err := r.ReadAt(data, pos-1); err != nil {
		return 0, err
	}

	var retval uint8
	retval = data[0]

	return retval, nil
}

// read unsigned 32-bit integer
func readuint32(r io.ReaderAt, pos uint32) (uint32, error) {
	pos2 := int64(pos)

	data := make([]byte, 4)
	if _, err := r.ReadAt(data, pos2-1); err != nil {
		return 0, nil
	}

	var retval uint32
	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.LittleEndian, &retval); err != nil {
		return 0, err
	}

	return retval, nil
}

// read unsigned 128-bit integer
func readuint128(r io.ReaderAt, pos uint32) (*big.Int, error) {
	pos2 := int64(pos)

	retval := big.NewInt(0)
	data := make([]byte, 16)

	if _, err := r.ReadAt(data, pos2-1); err != nil {
		return nil, err
	}

	// little endian to big endian
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
	retval.SetBytes(data)

	return retval, nil
}

// read string
func readstr(r io.ReaderAt, pos uint32) (string, error) {
	pos2 := int64(pos)
	var retval string

	lenbyte := make([]byte, 1)
	if _, err := r.ReadAt(lenbyte, pos2); err != nil {
		return "", err
	}

	strlen := lenbyte[0]
	data := make([]byte, strlen)

	if _, err := r.ReadAt(data, pos2+1); err != nil {
		return "", err
	}

	retval = string(data[:strlen])
	return retval, nil
}

// read float
func readfloat(r io.ReaderAt, pos uint32) (float32, error) {
	pos2 := int64(pos)
	var retval float32

	data := make([]byte, 4)

	if _, err := r.ReadAt(data, pos2-1); err != nil {
		return 0, err
	}

	buf := bytes.NewReader(data)

	if err := binary.Read(buf, binary.LittleEndian, &retval); err != nil {
		return 0, err
	}

	return retval, nil
}

func (r *Reader) All(ipaddress string) (Record, error) {
	return r.query(ipaddress, AllField)
}

func (r *Reader) Specific(ipaddress string, fields uint32) (Record, error) {
	return r.query(ipaddress, fields)
}

func (r *Reader) CountryCode(ipaddress string) (string, error) {
	record, err := r.query(ipaddress, CountryCodeField)
	return record.CountryCode, err
}

func (r *Reader) CountryName(ipaddress string) (string, error) {
	record, err := r.query(ipaddress, CountryNameField)
	return record.CountryName, err
}

func (r *Reader) Region(ipaddress string) (string, error) {
	record, err := r.query(ipaddress, RegionField)
	return record.Region, err
}

func (r *Reader) City(ipaddress string) (string, error) {
	record, err := r.query(ipaddress, CityField)
	return record.City, err
}

func (r *Reader) Isp(ipaddress string) (string, error) {
	record, err := r.query(ipaddress, IspField)
	return record.Isp, err
}

func (r *Reader) Latitude(ipaddress string) (float32, error) {
	record, err := r.query(ipaddress, LatitudeField)
	return record.Latitude, err
}

func (r *Reader) Longitude(ipaddress string) (float32, error) {
	record, err := r.query(ipaddress, LongitudeField)
	return record.Longitude, err
}

func (r *Reader) Domain(ipaddress string) (string, error) {
	record, err := r.query(ipaddress, DomainField)
	return record.Domain, err
}

func (r *Reader) ZipCode(ipaddress string) (string, error) {
	record, err := r.query(ipaddress, ZipCodeField)
	return record.ZipCode, err
}

func (r *Reader) TimeZone(ipaddress string) (string, error) {
	record, err := r.query(ipaddress, TimezoneField)
	return record.TimeZone, err
}

func (r *Reader) NetSpeed(ipaddress string) (string, error) {
	record, err := r.query(ipaddress, NetSpeedField)
	return record.NetSpeed, err
}

func (r *Reader) IddCode(ipaddress string) (string, error) {
	record, err := r.query(ipaddress, IddCodeField)
	return record.IddCode, err
}

func (r *Reader) AreaCode(ipaddress string) (string, error) {
	record, err := r.query(ipaddress, AreaCodeField)
	return record.AreaCode, err
}

func (r *Reader) WeatherStationCode(ipaddress string) (string, error) {
	record, err := r.query(ipaddress, WeatherStationCodeField)
	return record.WeatherStationCode, err
}

func (r *Reader) WeatherStationName(ipaddress string) (string, error) {
	record, err := r.query(ipaddress, WeatherStationNameField)
	return record.WeatherStationName, err
}

func (r *Reader) Mcc(ipaddress string) (string, error) {
	record, err := r.query(ipaddress, MccField)
	return record.Mcc, err
}

func (r *Reader) Mnc(ipaddress string) (string, error) {
	record, err := r.query(ipaddress, MncField)
	return record.Mnc, err
}

func (r *Reader) MobileBrand(ipaddress string) (string, error) {
	record, err := r.query(ipaddress, MobileBrandField)
	return record.MobileBrand, err
}

func (r *Reader) Elevation(ipaddress string) (float32, error) {
	record, err := r.query(ipaddress, ElevationField)
	return record.Elevation, err
}

func (r *Reader) UsageType(ipaddress string) (string, error) {
	record, err := r.query(ipaddress, UsageTypeField)
	return record.UsageType, err
}

// main query
func (r *Reader) query(ipaddress string, mode uint32) (record Record, err error) {
	// check IP type and return IP number & index (if exists)
	iptype, ipno, ipindex := r.checkip(ipaddress)

	if iptype == 0 {
		return record, ErrInvalidIpAddress
	}

	var colsize uint32
	var baseaddr uint32
	var low uint32
	var high uint32
	var mid uint32
	var rowoffset uint32
	var rowoffset2 uint32

	ipfrom := big.NewInt(0)
	ipto := big.NewInt(0)
	maxip := big.NewInt(0)

	if iptype == 4 {
		baseaddr = r.meta.ipv4databaseaddr
		high = r.meta.ipv4databasecount
		maxip = maxIPv4Range
		colsize = r.meta.ipv4columnsize
	} else {
		baseaddr = r.meta.ipv6databaseaddr
		high = r.meta.ipv6databasecount
		maxip = maxIPv6Range
		colsize = r.meta.ipv6columnsize
	}

	// reading index
	if ipindex > 0 {
		if low, err = readuint32(r.r, ipindex); err != nil {
			return
		}

		if high, err = readuint32(r.r, ipindex+4); err != nil {
			return
		}
	}

	if ipno.Cmp(maxip) >= 0 {
		ipno = ipno.Sub(ipno, big.NewInt(1))
	}

	for low <= high {
		mid = (low + high) >> 1
		rowoffset = baseaddr + (mid * colsize)
		rowoffset2 = rowoffset + colsize

		if iptype == 4 {
			ipfrom32, err := readuint32(r.r, rowoffset)
			if err != nil {
				return record, err
			}
			ipto32, err := readuint32(r.r, rowoffset2)
			if err != nil {
				return record, err
			}

			ipfrom = big.NewInt(int64(ipfrom32))
			ipto = big.NewInt(int64(ipto32))
		} else {
			if ipfrom, err = readuint128(r.r, rowoffset); err != nil {
				return
			}
			if ipto, err = readuint128(r.r, rowoffset2); err != nil {
				return
			}
		}

		if ipno.Cmp(ipfrom) >= 0 && ipno.Cmp(ipto) < 0 {
			if iptype == 6 {
				rowoffset = rowoffset + 12 // coz below is assuming AllField columns are 4 bytes, so got 12 left to go to make 16 bytes total
			}

			var stroffset uint32

			if mode&CountryCodeField == 1 && r.fieldsEnabled.country {
				if stroffset, err = readuint32(r.r, rowoffset+r.positionsOffset.country); err != nil {
					return
				}
				if record.CountryCode, err = readstr(r.r, stroffset); err != nil {
					return
				}
			}

			if mode&CountryNameField != 0 && r.fieldsEnabled.country {
				if stroffset, err = readuint32(r.r, rowoffset+r.positionsOffset.country); err != nil {
					return
				}
				if record.CountryName, err = readstr(r.r, stroffset+3); err != nil {
					return
				}
			}

			if mode&RegionField != 0 && r.fieldsEnabled.region {
				if stroffset, err = readuint32(r.r, rowoffset+r.positionsOffset.region); err != nil {
					return
				}
				if record.Region, err = readstr(r.r, stroffset); err != nil {
					return
				}
			}

			if mode&CityField != 0 && r.fieldsEnabled.city {
				if stroffset, err = readuint32(r.r, rowoffset+r.positionsOffset.city); err != nil {
					return
				}
				if record.City, err = readstr(r.r, stroffset); err != nil {
					return
				}
			}

			if mode&IspField != 0 && r.fieldsEnabled.isp {
				if stroffset, err = readuint32(r.r, rowoffset+r.positionsOffset.isp); err != nil {
					return
				}
				if record.Isp, err = readstr(r.r, stroffset); err != nil {
					return
				}
			}

			if mode&LatitudeField != 0 && r.fieldsEnabled.latitude {
				if record.Latitude, err = readfloat(r.r, rowoffset+r.positionsOffset.latitude); err != nil {
					return
				}
			}

			if mode&LongitudeField != 0 && r.fieldsEnabled.longitude {
				if record.Longitude, err = readfloat(r.r, rowoffset+r.positionsOffset.longitude); err != nil {
					return
				}
			}

			if mode&DomainField != 0 && r.fieldsEnabled.domain {
				if stroffset, err = readuint32(r.r, rowoffset+r.positionsOffset.domain); err != nil {
					return
				}
				if record.Domain, err = readstr(r.r, stroffset); err != nil {
					return
				}
			}

			if mode&ZipCodeField != 0 && r.fieldsEnabled.zipcode {
				if stroffset, err = readuint32(r.r, rowoffset+r.positionsOffset.zipcode); err != nil {
					return
				}
				if record.ZipCode, err = readstr(r.r, stroffset); err != nil {
					return
				}
			}

			if mode&TimezoneField != 0 && r.fieldsEnabled.timezone {
				if stroffset, err = readuint32(r.r, rowoffset+r.positionsOffset.timezone); err != nil {
					return
				}
				if record.TimeZone, err = readstr(r.r, stroffset); err != nil {
					return
				}
			}

			if mode&NetSpeedField != 0 && r.fieldsEnabled.netspeed {
				if stroffset, err = readuint32(r.r, rowoffset+r.positionsOffset.netspeed); err != nil {
					return
				}
				if record.NetSpeed, err = readstr(r.r, stroffset); err != nil {
					return
				}
			}

			if mode&IddCodeField != 0 && r.fieldsEnabled.iddcode {
				if stroffset, err = readuint32(r.r, rowoffset+r.positionsOffset.iddcode); err != nil {
					return
				}
				if record.IddCode, err = readstr(r.r, stroffset); err != nil {
					return
				}
			}

			if mode&AreaCodeField != 0 && r.fieldsEnabled.areacode {
				if stroffset, err = readuint32(r.r, rowoffset+r.positionsOffset.areacode); err != nil {
					return
				}
				if record.AreaCode, err = readstr(r.r, stroffset); err != nil {
					return
				}
			}

			if mode&WeatherStationCodeField != 0 && r.fieldsEnabled.weatherstationcode {
				if stroffset, err = readuint32(r.r, rowoffset+r.positionsOffset.weatherstationcode); err != nil {
					return
				}
				if record.WeatherStationCode, err = readstr(r.r, stroffset); err != nil {
					return
				}
			}

			if mode&WeatherStationNameField != 0 && r.fieldsEnabled.weatherstationname {
				if stroffset, err = readuint32(r.r, rowoffset+r.positionsOffset.weatherstationname); err != nil {
					return
				}
				if record.WeatherStationName, err = readstr(r.r, stroffset); err != nil {
					return
				}
			}

			if mode&MccField != 0 && r.fieldsEnabled.mcc {
				if stroffset, err = readuint32(r.r, rowoffset+r.positionsOffset.mcc); err != nil {
					return
				}
				if record.Mcc, err = readstr(r.r, stroffset); err != nil {
					return
				}

				record.Mcc = strings.Trim(record.Mcc, " -")
			}

			if mode&MncField != 0 && r.fieldsEnabled.mnc {
				if stroffset, err = readuint32(r.r, rowoffset+r.positionsOffset.mnc); err != nil {
					return
				}
				if record.Mnc, err = readstr(r.r, stroffset); err != nil {
					return
				}

				record.Mnc = strings.Trim(record.Mnc, " -")
			}

			if mode&MobileBrandField != 0 && r.fieldsEnabled.mobilebrand {
				if stroffset, err = readuint32(r.r, rowoffset+r.positionsOffset.mobilebrand); err != nil {
					return
				}
				if record.MobileBrand, err = readstr(r.r, stroffset); err != nil {
					return
				}

				record.MobileBrand = strings.Trim(record.MobileBrand, " -")
			}

			if mode&ElevationField != 0 && r.fieldsEnabled.elevation {
				if stroffset, err = readuint32(r.r, rowoffset+r.positionsOffset.elevation); err != nil {
					return
				}

				var sf string
				if sf, err = readstr(r.r, stroffset); err != nil {
					return
				}

				f, _ := strconv.ParseFloat(sf, 32)
				record.Elevation = float32(f)
			}

			if mode&UsageTypeField != 0 && r.fieldsEnabled.usagetype {
				if stroffset, err = readuint32(r.r, rowoffset+r.positionsOffset.usagetype); err != nil {
					return
				}
				if record.UsageType, err = readstr(r.r, stroffset); err != nil {
					return
				}
			}

			return record, nil
		} else {
			if ipno.Cmp(ipfrom) < 0 {
				high = mid - 1
			} else {
				low = mid + 1
			}
		}
	}

	return record, nil
}
