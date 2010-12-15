/*
 * CookerVersion.h
 *
 *  Created on: Jun 9, 2010
 *      Author: daniele
 */

#ifndef COOKERVERSION_H_
#define COOKERVERSION_H_

#include <boost/regex.hpp>

const boost::regex required_cooker_version("^1\\.1\\.\\d+\\.\\d+");
const std::string printable_required_cooker_version = "1.0";

#endif /* COOKERVERSION_H_ */
